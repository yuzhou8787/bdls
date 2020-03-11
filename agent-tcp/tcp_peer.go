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
	"net"
	"time"
)

// state to toggle for connection reading
type readState byte

const (
	stateReadSize readState = iota
	stateReadMessage
)

// Peer contains information related to a connection
type Peer struct {
	readState    readState
	conn         net.Conn
	agent        *agentImpl
	writeTimeout time.Duration
}

// RemoteAddr should return peer's address as identity
func (p *Peer) RemoteAddr() net.Addr { return p.conn.RemoteAddr() }

// Send message to this peer
func (p *Peer) Send(out []byte) error {
	// we also need to append a 4Bytes length before sending
	buf := make([]byte, len(out)+4)
	binary.LittleEndian.PutUint32(buf, uint32(len(out)))
	copy(buf[4:], out)
	return p.agent.watcher.WriteTimeout(p, p.conn, buf, time.Now().Add(p.agent.writeTimeout.Load().(time.Duration)))
}
