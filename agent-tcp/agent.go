// Copyright (c) 2020 Sperax
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package agent

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/bdls/consensus"
	"github.com/xtaci/bdls/timer"
	"github.com/xtaci/gaio"
)

const (
	// Frame format:
	// |MessageSize(4bytes)| Message(MessageSize) ... |
	MessageSize = 4

	// Message max length
	MaxMessageLength = 1 << 20

	// timeout for a unresponsive connection
	defaultReadTimeout  = 10 * time.Second
	defaultWriteTimeout = 10 * time.Second
)

// ConfirmedState represents a tuple for confirmed state with it's height
type ConfirmedState struct {
	Height uint64 // height for this confirmation
	Round  uint64 // round for this confirmation
	State  []byte // the confirmed state
}

// Agent defines a tcp node proxy for BDLS consensus algorithm
type Agent struct {
	*agentImpl
}

type agentImpl struct {
	// the associated listener for listening incoming broadcast
	listener *net.TCPListener

	// the associated watcher for sending messages to peers
	watcher      *gaio.Watcher
	readTimeout  atomic.Value
	writeTimeout atomic.Value

	// consensus
	consensus  *consensus.Consensus
	lastHeight uint64 // track last height

	// and it's lock
	consensusMu sync.Mutex

	// confirmed states from consensus algorithm
	confirmedStates []ConfirmedState
	// and notification
	chNotifyConfirmed chan struct{}

	// mark the connection closing
	die     chan struct{}
	dieOnce sync.Once

	// timed scheduler
	timedSched *timer.TimedSched
}

// NewAgent will create a new agent talking BDLS consensus protocol.
//
// 'listener': listener accepts incoming connection and receive messages
//
// 'config': the config for consensus
func NewAgent(listener *net.TCPListener, config *consensus.Config) (*Agent, error) {
	// listener must be specified
	if listener == nil {
		return nil, ErrListenerNotSpecified
	}

	// create consensus control object
	consensus, err := consensus.NewConsensus(config)
	if err != nil {
		return nil, err
	}

	// setup
	agent := new(agentImpl)
	watcher, err := gaio.NewWatcher()
	if err != nil {
		return nil, err
	}

	agent.consensus = consensus
	agent.listener = listener
	agent.watcher = watcher
	agent.die = make(chan struct{})
	agent.chNotifyConfirmed = make(chan struct{}, 1)
	agent.lastHeight, _, _ = consensus.CurrentState()

	agent.readTimeout.Store(defaultReadTimeout)
	agent.writeTimeout.Store(defaultReadTimeout)

	// create a timed scheduler for this agent to schedule
	agent.timedSched = timer.NewTimedSched(1)

	// start goroutines
	go agent.acceptor()
	go agent.readLoop()

	// update will schedule itself periodically
	agent.timedSched.Put(agent.update, time.Now().Add(20*time.Millisecond))

	// watcher finalizer for system resources
	wrapper := &Agent{agentImpl: agent}
	runtime.SetFinalizer(wrapper, func(wrapper *Agent) {
		wrapper.Close()
	})

	return wrapper, nil
}

// Close this agent immediately
func (agent *agentImpl) Close() {
	agent.dieOnce.Do(func() {
		agent.listener.Close()
		agent.watcher.Close()
		close(agent.die)
	})
}

// update will call consensus.Update perodically
func (agent *agentImpl) update() {
	select {
	case <-agent.die:
		log.Println(ErrClosed)
	default:
		// self-synchronized timed scheduling
		agent.consensusMu.Lock()
		agent.consensus.Update(time.Now())
		agent.consensusMu.Unlock()
		agent.timedSched.Put(agent.update, time.Now().Add(20*time.Millisecond))
	}
}

// acceptor will accept all incoming new connections
func (agent *agentImpl) acceptor() {
	for {
		conn, err := agent.listener.Accept()
		if err != nil {
			return
		}

		// read the first message
		peer := new(Peer)
		peer.readState = stateReadSize
		peer.conn = conn
		peer.agent = agent
		peer.writeTimeout = defaultWriteTimeout
		err = agent.watcher.ReadFull(peer, conn, make([]byte, MessageSize), time.Now().Add(agent.readTimeout.Load().(time.Duration)))
		if err != nil {
			return
		}
		agent.consensusMu.Lock()
		agent.consensus.AddPeer(peer)
		agent.consensusMu.Unlock()
	}
}

// readLoop will process all incoming messages from all connections,
// with the help of async-io
func (agent *agentImpl) readLoop() {
	w := agent.watcher
	for {
		results, err := w.WaitIO()
		if err != nil {
			return
		}

		// for read loop, we only process incoming message
		for _, res := range results {
			peer := res.Context.(*Peer)
			if res.Operation != gaio.OpRead {
				continue
			}
			if res.Error != nil {
				if res.Error != io.EOF {
					log.Println(res.Error)
				}
				// if error happens on a connection, we also need to remove it from
				// participants if it's a know participants
				agent.consensusMu.Lock()
				agent.consensus.RemovePeer(peer.RemoteAddr())
				agent.consensusMu.Unlock()
				continue
			}
			if res.Size <= 0 {
				continue
			}

			switch peer.readState {
			case stateReadSize:
				// submit read request to read full message
				length := binary.LittleEndian.Uint32(res.Buffer[:res.Size])
				if length > MaxMessageLength {
					continue
				}

				if length > 0 {
					peer.readState = stateReadMessage
					err := agent.watcher.ReadFull(peer, res.Conn, make([]byte, length), time.Now().Add(agent.readTimeout.Load().(time.Duration)))
					if err != nil {
						log.Println(err)
						return
					}
				}

			case stateReadMessage:
				agent.handleEstablished(res.Buffer[:res.Size])
				// submit read request to read size
				peer.readState = stateReadSize
				err = agent.watcher.ReadFull(peer, res.Conn, make([]byte, MessageSize), time.Now().Add(agent.readTimeout.Load().(time.Duration)))
				if err != nil {
					log.Println(err)
					return
				}
			}
		}
	}
}

func (agent *agentImpl) handleEstablished(message []byte) {
	agent.consensusMu.Lock()
	defer agent.consensusMu.Unlock()
	err := agent.consensus.ReceiveMessage(message, time.Now())
	if err != nil {
		//log.Println(err)
	}

	// a confirmation
	height, round, state := agent.consensus.CurrentState()
	if height > agent.lastHeight {
		agent.confirmedStates = append(agent.confirmedStates, ConfirmedState{height, round, state})
		agent.lastHeight = height
		select {
		case agent.chNotifyConfirmed <- struct{}{}:
		default:
			return
		}
	}
}

// Add a peer to this node
func (agent *agentImpl) AddPeer(conn *net.TCPConn) error {
	agent.consensusMu.Lock()
	defer agent.consensusMu.Unlock()

	// init new peer
	peer := new(Peer)
	peer.conn = conn
	peer.readState = stateReadSize
	peer.writeTimeout = defaultWriteTimeout
	peer.agent = agent

	if agent.consensus.AddPeer(peer) {
		return agent.watcher.ReadFull(peer, conn, make([]byte, MessageSize), time.Now().Add(agent.readTimeout.Load().(time.Duration)))
	}
	log.Println(ErrPeerExists)
	return ErrPeerExists
}

// SetConsensusLatency sets the latency for consensus protocol
func (agent *agentImpl) SetConsensusLatency(latency time.Duration) {
	agent.consensusMu.Lock()
	defer agent.consensusMu.Unlock()
	agent.consensus.SetLatency(latency)
}

// Propose submits a new state awaiting to be finalized with consensus protocol
func (agent *agentImpl) Propose(b consensus.State) {
	agent.consensusMu.Lock()
	defer agent.consensusMu.Unlock()
	agent.consensus.Propose(b)
}

// Wait waits until a new state is confirmed by consensus protocol
func (agent *agentImpl) Wait() ([]ConfirmedState, error) {
	for {
		var confirmedStates []ConfirmedState
		agent.consensusMu.Lock()
		confirmedStates = agent.confirmedStates
		agent.confirmedStates = nil
		agent.consensusMu.Unlock()

		if confirmedStates != nil {
			return confirmedStates, nil
		}

		select {
		case <-agent.chNotifyConfirmed:
		case <-agent.die:
			return nil, ErrClosed
		}
	}
}

// SetReadTimeout sets the read timeout for each read operation
func (agent *agentImpl) SetReadTimeout(d time.Duration) { agent.readTimeout.Store(d) }

// SetWriteTimeout sets the write timeout for each write operation
func (agent *agentImpl) SetWriteTimeout(d time.Duration) { agent.writeTimeout.Store(d) }
