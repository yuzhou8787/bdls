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
	"crypto/cipher"
	"crypto/ecdsa"
	"encoding/binary"
	io "io"
	"log"
	"net"
	"sync"
	"time"

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
	// connECDHInit: the peer has sent it's ECDHInit
	connECDHInit
	// connAuthenticated: the peer has authenticated
	connAuthenticated
)

// TCPPeer contains information related to a tcp connection
type TCPPeer struct {
	connState connState        // connection state
	conn      net.Conn         // the connection to this peer
	publicKey *ecdsa.PublicKey // if it's not nil, the peer is known(authenticated in some way)

	// message queues and their notifications
	consensusMessages  [][]byte      // all pending outgoing consensus messages to this peer
	chConsensusMessage chan struct{} // notification on new consensus data

	// internal
	internalMessages   [][]byte      // all pending outgoing internal messages to this peer.
	chInternalMessages chan struct{} // notification on new internal exchange data

	// AEAD for authenticated peer
	aead cipher.AEAD

	// peer closing signal
	die     chan struct{}
	dieOnce sync.Once

	// mutex for all fields
	sync.Mutex
}

// NewTCPPeer creates a consensus peer based on net.Conn and and async-io(gaio) watcher for sending
func NewTCPPeer(conn net.Conn) *TCPPeer {
	p := new(TCPPeer)
	p.chConsensusMessage = make(chan struct{}, 1)
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
	p.notifyPending()
	return nil
}

// notifyPending output
func (p *TCPPeer) notifyPending() {
	select {
	case p.chConsensusMessage <- struct{}{}:
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
			case CommandType_ECDH_INIT:
				if err := p.handleECDHInit(&msg); err != nil {
					log.Println(err)
					return
				}
			case CommandType_ECDH_REPLY:
			case CommandType_CONSENSUS:
			}
		}
	}
}

//
func (p *TCPPeer) handleECDHInit(msg *TCP) error {
	if p.connState == connInit { // only when in init status
		// peer sent init, then we should send
		return nil
	} else {
		return ErrStateIncorrectECDHInit
	}
}

// sendLoop for consensus message transmission
func (p *TCPPeer) sendLoop() {
	defer p.Close()

	var pending [][]byte
	var msg TCP
	msg.Command = CommandType_CONSENSUS
	msg.Nonce = make([]byte, p.aead.NonceSize())
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
