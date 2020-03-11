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

package consensus

import (
	"crypto/ecdsa"
	"time"
)

const (
	// ConfigMinimumParticipants is the minimum number of participant allow in consensus protocol
	ConfigMinimumParticipants = 4
)

// Config is to config the parameters of BDLS consensus protocol
type Config struct {
	// the starting time point for consensus
	Epoch time.Time
	// CurrentHeight
	CurrentHeight uint64
	// CurrentState
	CurrentState State
	// PrivateKey
	PrivateKey *ecdsa.PrivateKey
	// Consensus Group
	Participants []*ecdsa.PublicKey

	// StateCompare is a function from user to compare states,
	// The result will be 0 if a==b, -1 if a < b, and +1 if a > b.
	// Ususally this would be block header in blockchain, or replication log in database,
	// users should check fields in block header to make comparsion.
	StateCompare func(a State, b State) int

	// StateValidate is a function from user to validate the integrity of
	// a state data.
	StateValidate func(State) bool

	// StateHash is a function from user to return a hash to uniquely identifies
	// a state.
	StateHash func(State) StateHash
}

// VerifyConfig verifies the integrity of this config when creating new consensus object
func VerifyConfig(c *Config) error {
	if c.Epoch.IsZero() {
		return ErrConfigEpoch
	}

	if c.CurrentState == nil {
		return ErrConfigStateNil
	}

	if c.StateCompare == nil {
		return ErrConfigLess
	}

	if c.StateValidate == nil {
		return ErrConfigValidateState
	}

	if c.PrivateKey == nil {
		return ErrConfigPrivateKey
	}

	if len(c.Participants) < ConfigMinimumParticipants {
		return ErrConfigParticipants
	}

	return nil
}
