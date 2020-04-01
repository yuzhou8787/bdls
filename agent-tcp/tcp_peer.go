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
	fmt "fmt"
	io "io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/Sperax/bdls"
	"github.com/Sperax/bdls/crypto/blake2b"
	"github.com/Sperax/bdls/timer"
	proto "github.com/gogo/protobuf/proto"
)

// fake address for Pipe
type fakeAddress string

func (fakeAddress) Network() string  { return "pipe" }
func (f fakeAddress) String() string { return string(f) }

const (
	// Frame format:
	// |MessageLength(4bytes)| Message(MessageLength) ... |
	MessageLength = 4

	// Message max length(32MB)
	MaxMessageLength = 32 * 1024 * 1024

	// timeout for a unresponsive connection
	defaultReadTimeout  = 60 * time.Second
	defaultWriteTimeout = 60 * time.Second

	// ChallengeSize
	ChallengeSize = 128
)

// authenticationState is the authentication status for both peer
type authenticationState byte

// peer initated public-key authentication status
const (
	// peerNotAuthenticated: the peer has just connected
	peerNotAuthenticated authenticationState = iota
	// peerSentAuthkey: the peer begined it's public key authentication,
	// and we've sent out our challenge.
	peerAuthkeyReceived
	// peerAuthenticated: the peer has been authenticated to it's public key
	peerAuthenticated
	// peer failed to accept our challenge
	peerAuthenticatedFailed
)

// local initated public key authentication status
const (
	localNotAuthenticated authenticationState = iota
	// localSentAuthKey: we have sent auth key command to the peer
	localAuthKeySent
	// localChallengeReceived: we have received challenge from peer
	localChallengeReceived
	// localChallengeResponsed: we have sent challenge to the peer
	localChallengeResponsed
)

// A TCPAgent binds consensus core to a TCPAgent object, which may have multiple TCPPeer
type TCPAgent struct {
	consensus  *bdls.Consensus   // the consensus core
	privateKey *ecdsa.PrivateKey // a private key to sign messages to this peer
	peers      []*TCPPeer

	die     chan struct{}
	dieOnce sync.Once
	sync.Mutex
}

// NewTCPAgent initiate a TCPAgent which talks consensus protocol among peers
func NewTCPAgent(consensus *bdls.Consensus, privateKey *ecdsa.PrivateKey) *TCPAgent {
	agent := new(TCPAgent)
	agent.consensus = consensus
	agent.privateKey = privateKey
	return agent
}

// AddPeer adds a peer to this agent
func (agent *TCPAgent) AddPeer(p *TCPPeer) bool {
	agent.Lock()
	defer agent.Unlock()

	select {
	case <-agent.die:
		return false
	default:
		agent.peers = append(agent.peers, p)
		return agent.consensus.AddPeer(p)
	}
}

// RemovePeer removes a TCPPeer from this agent
func (agent *TCPAgent) RemovePeer(p *TCPPeer) bool {
	agent.Lock()
	defer agent.Unlock()

	peerAddress := p.RemoteAddr().String()
	for k := range agent.peers {
		if agent.peers[k].RemoteAddr().String() == peerAddress {
			copy(agent.peers[k:], agent.peers[k+1:])
			agent.peers = agent.peers[:len(agent.peers)-1]
			return true
		}
	}
	return false
}

// Close stops all activities on this agent
func (agent *TCPAgent) Close() {
	agent.Lock()
	defer agent.Lock()

	agent.dieOnce.Do(func() {
		close(agent.die)
		// close all peers
		for k := range agent.peers {
			agent.peers[k].Close()
		}
	})
}

// Update is the consensus updater
func (agent *TCPAgent) Update() {
	agent.Lock()
	defer agent.Unlock()

	select {
	case <-agent.die:
	default:
		// call consensus update
		_ = agent.consensus.Update(time.Now())
		timer.SystemTimedSched.Put(agent.Update, time.Now().Add(20*time.Millisecond))
	}
}

// Propose a state, awaiting to be finalized at next height.
func (agent *TCPAgent) Propose(s bdls.State) {
	agent.Lock()
	defer agent.Unlock()
	agent.consensus.Propose(s)
}

// GetLatestState returns latest state
func (agent *TCPAgent) GetLatestState() (height uint64, round uint64, data bdls.State) {
	agent.Lock()
	defer agent.Unlock()
	return agent.consensus.CurrentState()
}

// handleConsensusMessage will be called if TCPPeer received a consensus message
func (agent *TCPAgent) handleConsensusMessage(bts []byte) error {
	agent.Lock()
	defer agent.Unlock()
	return agent.consensus.ReceiveMessage(bts, time.Now())
}

// TCPPeer contains information related to a tcp connection peer
type TCPPeer struct {
	agent          *TCPAgent           // the agent it belongs to
	conn           net.Conn            // the connection to this peer
	peerAuthStatus authenticationState // peer authentication status
	// the announced public key of the peer, only becomes valid if peerAuthStatus == peerAuthenticated
	peerPublicKey *ecdsa.PublicKey

	// local authentication status
	localAuthState authenticationState

	// the challenge for the peer if peer requested key authentication
	challengePlainText []byte

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

// NewTCPPeer creates a TCPPeer with protocol over this connection
func NewTCPPeer(conn net.Conn, agent *TCPAgent) *TCPPeer {
	p := new(TCPPeer)
	p.chConsensusMessage = make(chan struct{}, 1)
	p.chInternalMessage = make(chan struct{}, 1)
	p.conn = conn
	p.agent = agent
	p.die = make(chan struct{})
	// we start readLoop & sendLoop for each connection
	go p.readLoop()
	go p.sendLoop()
	return p
}

// RemoteAddr implements PeerInterface, GetPublicKey returns peer's
// public key, returns nil if peer's has not authenticated it's public-key
func (p *TCPPeer) GetPublicKey() *ecdsa.PublicKey {
	p.Lock()
	defer p.Unlock()
	if p.peerAuthStatus == peerAuthenticated {
		log.Println("get public key:", p.peerPublicKey)
		return p.peerPublicKey
	}
	return nil
}

// RemoteAddr implements PeerInterface, returns peer's address as connection identity
func (p *TCPPeer) RemoteAddr() net.Addr {
	if p.conn.RemoteAddr().Network() == "pipe" {
		return fakeAddress(fmt.Sprint(unsafe.Pointer(p)))
	}
	return p.conn.RemoteAddr()
}

// Send implements PeerInterface, to send message to this peer
func (p *TCPPeer) Send(out []byte) error {
	p.Lock()
	defer p.Unlock()
	p.consensusMessages = append(p.consensusMessages, out)
	p.notifyConsensusMessage()
	return nil
}

// notifyConsensusMessage notifies there're message pending to send
func (p *TCPPeer) notifyConsensusMessage() {
	select {
	case p.chConsensusMessage <- struct{}{}:
	default:
	}
}

// notifyInternalMessage, notifies there're internal messages pending to send
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

// InitiatePublicKeyAuthentication will initate a procedure to convince
// the other peer to trust my ownership of public key
func (p *TCPPeer) InitiatePublicKeyAuthentication() error {
	if p.localAuthState == localNotAuthenticated {
		auth := KeyAuthInit{}
		auth.X = p.agent.privateKey.PublicKey.X.Bytes()
		auth.Y = p.agent.privateKey.PublicKey.Y.Bytes()

		// proto marshal
		bts, err := proto.Marshal(&auth)
		if err != nil {
			panic(err)
		}

		g := Gossip{Command: CommandType_KEY_AUTH_INIT, Message: bts}
		// proto marshal
		out, err := proto.Marshal(&g)
		if err != nil {
			panic(err)
		}

		// enqueue
		p.internalMessages = append(p.internalMessages, out)
		p.notifyInternalMessage()
		p.localAuthState = localAuthKeySent
		return nil
	} else {
		return ErrPeerKeyAuthInit
	}
}

// handleGossip will process all messages from this peer based on it's message types
func (p *TCPPeer) handleGossip(msg *Gossip) error {
	p.Lock()
	defer p.Unlock()

	switch msg.Command {
	case CommandType_NOP: // NOP can be used for connection keepalive
	case CommandType_KEY_AUTH_INIT:
		// peer wants to authenticate it's publickey
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
		// I received a challenge from peer
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
		// peer sends back a challenge reply to authenticate it's publickey
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
		// a consensus message
		p.agent.handleConsensusMessage(msg.Message)
	default:
		log.Println("msg", msg.Command)
	}
	return nil
}

// peer initiated key authentication
func (p *TCPPeer) handleKeyAuthInit(authKey *KeyAuthInit) error {
	// only when in init status, authentication process cannot rollback
	// to prevent from malicious re-authentication
	if p.peerAuthStatus == peerNotAuthenticated {
		// stored announced key
		p.peerPublicKey = &ecdsa.PublicKey{bdls.DefaultCurve, big.NewInt(0).SetBytes(authKey.X), big.NewInt(0).SetBytes(authKey.Y)}
		// create ephermal key for authentication
		ephemeral, err := ecdsa.GenerateKey(bdls.DefaultCurve, rand.Reader)
		if err != nil {
			panic(err)
		}
		// derive secret
		secret := ECDH(p.peerPublicKey, ephemeral)

		// create challenge texts and encode
		p.challengePlainText = make([]byte, ChallengeSize)
		_, err = io.ReadFull(rand.Reader, p.challengePlainText)
		if err != nil {
			panic(err)
		}

		// iv
		iv := make([]byte, aes.BlockSize)
		_, err = io.ReadFull(rand.Reader, iv)
		if err != nil {
			panic(err)
		}

		// sha the secret to create fixed 32bytes key
		key := blake2b.Sum256(secret.Bytes())

		// encrypt using AES-256-CFB
		block, err := aes.NewCipher(key[:])
		if err != nil {
			panic(err)
		}

		stream := cipher.NewCFBEncrypter(block, iv)
		cipherText := make([]byte, ChallengeSize)
		stream.XORKeyStream(cipherText, p.challengePlainText)

		var challenge KeyAuthChallenge
		challenge.X = ephemeral.PublicKey.X.Bytes()
		challenge.Y = ephemeral.PublicKey.Y.Bytes()
		challenge.CipherText = cipherText
		challenge.IV = iv

		// proto marshal
		bts, err := proto.Marshal(&challenge)
		if err != nil {
			panic(err)
		}

		g := Gossip{Command: CommandType_KEY_AUTH_CHALLENGE, Message: bts}
		// proto marshal
		out, err := proto.Marshal(&g)
		if err != nil {
			panic(err)
		}

		// enqueue
		p.internalMessages = append(p.internalMessages, out)
		p.notifyInternalMessage()

		// state shift
		p.peerAuthStatus = peerAuthkeyReceived
		return nil
	} else {
		return ErrPeerKeyAuthInit
	}
}

// peer issued a challenge to me
func (p *TCPPeer) handleKeyAuthChallenge(challenge *KeyAuthChallenge) error {
	if p.localAuthState == localAuthKeySent {
		// use ECDH to recover shared-key
		pubkey := &ecdsa.PublicKey{bdls.DefaultCurve, big.NewInt(0).SetBytes(challenge.X), big.NewInt(0).SetBytes(challenge.Y)}
		// derive secret with my private key
		secret := ECDH(pubkey, p.agent.privateKey)

		// sha the secret to create fixed 32bytes key
		key := blake2b.Sum256(secret.Bytes())
		// decrypt using AES-256-CFB with shared-key
		block, err := aes.NewCipher(key[:])
		if err != nil {
			panic(err)
		}
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

		g := Gossip{Command: CommandType_KEY_AUTH_CHALLENGE_REPLY, Message: bts}
		// proto marshal
		out, err := proto.Marshal(&g)
		if err != nil {
			panic(err)
		}

		// enqueue
		p.internalMessages = append(p.internalMessages, out)
		p.notifyInternalMessage()

		// state shift
		p.localAuthState = localChallengeReceived
		return nil
	} else {
		return ErrPeerKeyAuthChallenge
	}
}

// peer replieds my challenge
func (p *TCPPeer) handleKeyAuthChallengeReply(response *KeyAuthChallengeReply) error {
	if p.peerAuthStatus == peerAuthkeyReceived {
		if bytes.Equal(p.challengePlainText, response.PlainText) {
			p.challengePlainText = nil
			p.peerAuthStatus = peerAuthenticated
			return nil
		} else {
			p.peerAuthStatus = peerAuthenticatedFailed
			log.Println("perr authenticated failed")
			return ErrPeerAuthenticatedFailed
		}
	} else {
		return ErrPeerKeyAuthInit
	}
}

// readLoop is for reading message packets from peer
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
				log.Println("readfull:", err)
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
				log.Println("readfull:", err)
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
					log.Println("write:", err)
					return
				}

				// write message
				_, err = p.conn.Write(out)
				if err != nil {
					log.Println("write:", err)
					return
				}
			}
		case <-p.chInternalMessage:
			p.Lock()
			pending = p.internalMessages
			p.internalMessages = nil
			p.Unlock()

			for _, bts := range pending {
				binary.LittleEndian.PutUint32(msgLength, uint32(len(bts)))
				// write length
				_, err := p.conn.Write(msgLength)
				if err != nil {
					log.Println("write:", err)
					return
				}

				// write message
				_, err = p.conn.Write(bts)
				if err != nil {
					log.Println("write:", err)
					return
				}
			}

		case <-p.die:
			return
		}
	}
}
