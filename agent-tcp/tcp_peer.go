// BSD 3-Clause License
//
// Copyright (c) 2020, Sperax
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package agent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	io "io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/Sperax/bdls"
	proto "github.com/gogo/protobuf/proto"
)

const (
	// Frame format:
	// |MessageLength(4bytes)| Message(MessageLength) ... |
	MessageLength = 4

	// Message max length(32MB)
	MaxMessageLength = 32 * 1024 * 1024

	// timeout for a unresponsive connection
	defaultReadTimeout  = 10 * time.Second
	defaultWriteTimeout = 10 * time.Second
)

// connState is the connection state for this peer
type connState byte

const (
	// connInit: the peer has just connected
	connInit connState = iota
	// connAuthKey: the peer begined it's public key authentication
	connAuthKey
	// connChallengeSent: we have sent challenge to the peer
	connChallengeSent
	// connAuthenticated: the peer has authenticated it's public key
	connAuthenticated
)

// TCPPeer contains information related to a tcp connection peer
type TCPPeer struct {
	privateKey *ecdsa.PrivateKey // a private key to sign messages to this peer
	connState  connState         // connection state
	conn       net.Conn          // the connection to this peer
	publicKey  *ecdsa.PublicKey  // the public key the peer announced

	// the challenge
	announcedKey *ecdsa.PublicKey
	plaintext    []byte
	iv           []byte

	// message queues and their notifications
	consensusMessages  [][]byte      // all pending outgoing consensus messages to this peer
	chConsensusMessage chan struct{} // notification on new consensus data

	// internal
	internalMessages  [][]byte      // all pending outgoing internal messages to this peer.
	chInternalMessage chan struct{} // notification on new internal exchange data

	// peer closing signal
	die     chan struct{}
	dieOnce sync.Once

	// mutex for all fields
	sync.Mutex
}

// NewTCPPeer creates a consensus peer based on net.Conn and and async-io(gaio) watcher for sending
func NewTCPPeer(conn net.Conn, privateKey *ecdsa.PrivateKey) *TCPPeer {
	p := new(TCPPeer)
	p.privateKey = privateKey
	p.chConsensusMessage = make(chan struct{}, 1)
	p.chInternalMessage = make(chan struct{}, 1)
	p.conn = conn
	p.die = make(chan struct{})
	// we start readLoop first
	go p.readLoop()
	return p
}

// GetPublicKey returns peer's public key as identity
func (p *TCPPeer) GetPublicKey() *ecdsa.PublicKey {
	p.Lock()
	defer p.Unlock()
	return p.publicKey
}

// RemoteAddr should return peer's address as identity
func (p *TCPPeer) RemoteAddr() net.Addr { return p.conn.RemoteAddr() }

// Send message to this peer
func (p *TCPPeer) Send(out []byte) error {
	p.Lock()
	defer p.Unlock()
	p.consensusMessages = append(p.consensusMessages, out)
	p.notifyConsensusMessage()
	return nil
}

// notifyConsensusMessage output
func (p *TCPPeer) notifyConsensusMessage() {
	select {
	case p.chConsensusMessage <- struct{}{}:
	default:
	}
}

// notifyConsensusMessage output
func (p *TCPPeer) notifyInternalMessage() {
	select {
	case p.chInternalMessage <- struct{}{}:
	default:
	}
}

func (p *TCPPeer) Close() {
	p.dieOnce.Do(func() {
		close(p.die)
	})
}

// readLoop is for reading data from peer
func (p *TCPPeer) readLoop() {
	defer p.Close()
	msgLength := make([]byte, MessageLength)

	for {
		select {
		case <-p.die:
			return
		default:
			// read message size
			p.conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
			_, err := io.ReadFull(p.conn, msgLength)
			if err != nil {
				return
			}

			// check length
			length := binary.LittleEndian.Uint32(msgLength)
			if length > MaxMessageLength {
				log.Println(err)
			}

			if length == 0 {
				log.Println("zero length")
				return
			}

			// read message bytes
			p.conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
			bts := make([]byte, length)
			_, err = io.ReadFull(p.conn, bts)
			if err != nil {
				log.Println(err)
				return
			}

			// unmarshal bytes to message
			var msg TCP
			err = proto.Unmarshal(bts, &msg)
			if err != nil {
				log.Println(err)
				return
			}

			// commands have related status
			switch msg.Command {
			case CommandType_NOP:
			case CommandType_CLIENT_AUTHKEY:
				var authKey ClientAuthKey
				err = proto.Unmarshal(bts, &authKey)
				if err != nil {
					log.Println(err)
					return
				}

				if err := p.handleClientAuthKey(&authKey); err != nil {
					log.Println(err)
					return
				}
			case CommandType_SERVER_CHALLENGE:
				var challenge ServerChallenge
				err = proto.Unmarshal(bts, &challenge)
				if err != nil {
					log.Println(err)
					return
				}

				if err := p.handleServerChallenge(&challenge); err != nil {
					log.Println(err)
					return
				}

			case CommandType_CLIENT_RESPONSE:
				var response ClientResposne
				err = proto.Unmarshal(bts, &response)
				if err != nil {
					log.Println(err)
					return
				}

				if err := p.handleClientResponse(&response); err != nil {
					log.Println(err)
					return
				}

			case CommandType_CONSENSUS:
			}
		}
	}
}

//
func (p *TCPPeer) handleClientAuthKey(authKey *ClientAuthKey) error {
	if p.connState == connInit { // when in init status
		// create ephermal key
		ephemeral, err := ecdsa.GenerateKey(bdls.DefaultCurve, rand.Reader)
		if err != nil {
			panic(err)
		}

		// ECDH
		x := big.NewInt(0).SetBytes(authKey.X)
		y := big.NewInt(0).SetBytes(authKey.Y)
		secret, _ := bdls.DefaultCurve.ScalarMult(x, y, ephemeral.D.Bytes())

		// stored announced key
		p.announcedKey = &ecdsa.PublicKey{bdls.DefaultCurve, x, y}

		// create challenge texts and encode
		p.plaintext = make([]byte, 1024)
		_, err = io.ReadFull(rand.Reader, p.plaintext)
		if err != nil {
			panic(err)
		}

		// iv
		p.iv = make([]byte, aes.BlockSize)
		_, err = io.ReadFull(rand.Reader, p.iv)
		if err != nil {
			panic(err)
		}

		// encrypt using AES-256-CFB
		block, err := aes.NewCipher(secret.Bytes())
		if err != nil {
			panic(err)
		}

		stream := cipher.NewCFBEncrypter(block, p.iv)
		cipherText := make([]byte, 1024)
		stream.XORKeyStream(cipherText, p.plaintext)

		var challenge ServerChallenge
		challenge.X = ephemeral.PublicKey.X.Bytes()
		challenge.Y = ephemeral.PublicKey.X.Bytes()
		challenge.CipherText = cipherText
		challenge.IV = p.iv

		// proto marshal
		bts, err := proto.Marshal(&challenge)
		if err != nil {
			panic(err)
		}

		// enqueue
		p.Lock()
		p.internalMessages = append(p.internalMessages, bts)
		p.Unlock()

		p.notifyInternalMessage()

		// state shift
		p.connState = connChallengeSent
		return nil
	} else {
		return ErrClientAuthKeyState
	}
}

func (p *TCPPeer) handleServerChallenge(challenge *ServerChallenge) error {
	// ECDH
	x := big.NewInt(0).SetBytes(challenge.X)
	y := big.NewInt(0).SetBytes(challenge.Y)
	secret, _ := bdls.DefaultCurve.ScalarMult(x, y, p.privateKey.D.Bytes())

	// encrypt using AES-256-CFB
	block, err := aes.NewCipher(secret.Bytes())
	if err != nil {
		panic(err)
	}

	// use secret to decrypt challenge
	stream := cipher.NewCFBDecrypter(block, challenge.IV)
	stream.XORKeyStream(challenge.CipherText, challenge.CipherText)

	// send back client challenge response
	var response ClientResposne
	response.PlainText = challenge.CipherText

	// proto marshal
	bts, err := proto.Marshal(&response)
	if err != nil {
		panic(err)
	}

	// enqueue
	p.Lock()
	p.internalMessages = append(p.internalMessages, bts)
	p.Unlock()

	p.notifyInternalMessage()
	return nil
}

//
func (p *TCPPeer) handleClientResponse(response *ClientResposne) error {
	if p.connState == connChallengeSent {
		if bytes.Equal(p.plaintext, response.PlainText) {
			p.publicKey = p.announcedKey
			p.plaintext = nil
			p.iv = nil
			p.connState = connAuthenticated
			return nil
		}
		return ErrInvalidClientResponse
	} else {
		return ErrClientAuthKeyState
	}
}

// sendLoop for consensus message transmission
func (p *TCPPeer) sendLoop() {
	defer p.Close()

	var pending [][]byte
	var msg TCP
	msg.Command = CommandType_CONSENSUS
	msgLength := make([]byte, MessageLength)

	for {
		select {
		case <-p.chConsensusMessage:
			p.Lock()
			pending = p.consensusMessages
			p.consensusMessages = nil
			p.Unlock()

			for _, bts := range pending {
				// we need to encapsulate consensus messages
				msg.Message = bts
				out, err := proto.Marshal(&msg)
				if err != nil {
					panic(err)
				}

				if len(out) > MaxMessageLength {
					panic("maximum message size exceeded")
				}

				binary.LittleEndian.PutUint32(msgLength, uint32(len(out)))
				p.conn.SetWriteDeadline(time.Now().Add(defaultWriteTimeout))
				// write length
				_, err = p.conn.Write(msgLength)
				if err != nil {
					log.Println(err)
					return
				}

				// write message
				_, err = p.conn.Write(out)
				if err != nil {
					log.Println(err)
					return
				}
			}

		case <-p.die:
			return
		}
	}
}
