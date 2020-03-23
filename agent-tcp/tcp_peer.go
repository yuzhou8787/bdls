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

	// ChallengeSize
	ChallengeSize = 128
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

type LockedConsensus struct {
	*bdls.Consensus
	sync.Mutex
}

// TCPPeer contains information related to a tcp connection peer
type TCPPeer struct {
	consensus     *LockedConsensus  // the consensus core
	privateKey    *ecdsa.PrivateKey // a private key to sign messages to this peer
	connState     connState         // connection state
	conn          net.Conn          // the connection to this peer
	peerPublicKey *ecdsa.PublicKey  // the announced public key of the peer, only becomes valid if connState == connAuthenticated

	// the challenge for the peer if peer requested key authentication
	plaintext []byte
	iv        []byte

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

// NewTCPPeer binds a connection to local consensus core, with a private key for some message signing
func NewTCPPeer(conn net.Conn, privateKey *ecdsa.PrivateKey, consensus *LockedConsensus) *TCPPeer {
	p := new(TCPPeer)
	p.privateKey = privateKey
	p.consensus = consensus
	p.chConsensusMessage = make(chan struct{}, 1)
	p.chInternalMessage = make(chan struct{}, 1)
	p.conn = conn
	p.die = make(chan struct{})
	// we start readLoop first
	go p.readLoop()
	go p.sendLoop()
	return p
}

// GetPublicKey returns peer's public key as identity
func (p *TCPPeer) GetPublicKey() *ecdsa.PublicKey {
	p.Lock()
	defer p.Unlock()
	if p.connState == connAuthenticated {
		return p.peerPublicKey
	}
	return nil
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

// Close terminates connection to this peer
func (p *TCPPeer) Close() {
	p.dieOnce.Do(func() {
		p.conn.Close()
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
			var gossip Gossip
			err = proto.Unmarshal(bts, &gossip)
			if err != nil {
				log.Println(err)
				return
			}

			err = p.handleGossip(&gossip)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

// handle TCP
func (p *TCPPeer) handleGossip(msg *Gossip) error {
	switch msg.Command {
	case CommandType_NOP:
	case CommandType_KEY_AUTH_INIT:
		var m KeyAuthInit
		err := proto.Unmarshal(msg.Message, &m)
		if err != nil {
			return err
		}

		err = p.handleKeyAuthInit(&m)
		if err != nil {
			return err
		}
	case CommandType_KEY_AUTH_CHALLENGE:
		var m KeyAuthChallenge
		err := proto.Unmarshal(msg.Message, &m)
		if err != nil {
			return err
		}

		err = p.handleKeyAuthChallenge(&m)
		if err != nil {
			return err
		}

	case CommandType_KEY_AUTH_CHALLENGE_REPLY:
		var m KeyAuthChallengeReply
		err := proto.Unmarshal(msg.Message, &m)
		if err != nil {
			return err
		}

		err = p.handleKeyAuthChallengeReply(&m)
		if err != nil {
			return err
		}

	case CommandType_CONSENSUS:
		p.consensus.Lock()
		p.consensus.ReceiveMessage(msg.Message, time.Now())
		p.consensus.Unlock()
	}
	return nil
}

//
func (p *TCPPeer) handleKeyAuthInit(authKey *KeyAuthInit) error {
	p.Lock()
	defer p.Unlock()

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
		p.peerPublicKey = &ecdsa.PublicKey{bdls.DefaultCurve, x, y}

		// create challenge texts and encode
		p.plaintext = make([]byte, ChallengeSize)
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
		cipherText := make([]byte, ChallengeSize)
		stream.XORKeyStream(cipherText, p.plaintext)

		var challenge KeyAuthChallenge
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
		p.internalMessages = append(p.internalMessages, bts)
		p.notifyInternalMessage()

		// state shift
		p.connState = connChallengeSent
		return nil
	} else {
		return ErrClientAuthKeyState
	}
}

func (p *TCPPeer) handleKeyAuthChallenge(challenge *KeyAuthChallenge) error {
	p.Lock()
	defer p.Unlock()

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
	var response KeyAuthChallengeReply
	response.PlainText = challenge.CipherText

	// proto marshal
	bts, err := proto.Marshal(&response)
	if err != nil {
		panic(err)
	}

	// enqueue
	p.internalMessages = append(p.internalMessages, bts)
	p.notifyInternalMessage()
	return nil
}

//
func (p *TCPPeer) handleKeyAuthChallengeReply(response *KeyAuthChallengeReply) error {
	p.Lock()
	defer p.Unlock()

	if p.connState == connChallengeSent {
		if bytes.Equal(p.plaintext, response.PlainText) {
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
	var msg Gossip
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
		case <-p.chInternalMessage:
			for _, bts := range pending {
				binary.LittleEndian.PutUint32(msgLength, uint32(len(bts)))
				// write length
				_, err := p.conn.Write(msgLength)
				if err != nil {
					log.Println(err)
					return
				}

				// write message
				_, err = p.conn.Write(bts)
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
