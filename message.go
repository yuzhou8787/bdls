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

package bdls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/Sperax/bdls/crypto/blake2b"
	"github.com/Sperax/bdls/crypto/btcec"
	proto "github.com/golang/protobuf/proto"
)

// ErrPubKey will be returned if error found while decoding message's public key
var ErrPubKey = errors.New("incorrect pubkey format")

// default elliptic curve for signing
var DefaultCurve elliptic.Curve = btcec.S256()

const (
	// SizeAxis defines bytes size of X-axis or Y-axis in a public key
	SizeAxis = 32
	// SignaturePrefix is the prefix for signing a consensus message
	SignaturePrefix = "===Sperax Signed Message===\n"
)

// PubKeyAxis defines X-axis or Y-axis in a public key
type PubKeyAxis [SizeAxis]byte

// Marshal implements protobuf MarshalTo
func (t PubKeyAxis) Marshal() ([]byte, error) {
	return t[:], nil
}

// MarshalTo implements protobuf MarshalTo
func (t *PubKeyAxis) MarshalTo(data []byte) (n int, err error) {
	copy(data, (*t)[:])
	return SizeAxis, nil
}

// Unmarshal implements protobuf Unmarshal
func (t *PubKeyAxis) Unmarshal(data []byte) error {
	// mor than 32 bytes, illegal axis
	if len(data) > SizeAxis {
		return ErrPubKey
	}

	// if data is less than 32 bytes, we MUST keep the leading 0 zeros.
	off := SizeAxis - len(data)
	copy((*t)[off:], data)
	return nil
}

// Size implements protobuf Size
func (t *PubKeyAxis) Size() int { return SizeAxis }

// MarshalJSON implements protobuf MarshalJSON
func (t PubKeyAxis) MarshalJSON() ([]byte, error) { return json.Marshal(t) }

// UnmarshalJSON implements protobuf UnmarshalJSON
func (t *PubKeyAxis) UnmarshalJSON(data []byte) error { return json.Unmarshal(data, t) }

// Coordinate encodes X-axis and Y-axis for a publickey in an array
type Coordinate [2 * SizeAxis]byte

// create coordinate from public key
func newCoordFromPubKey(pubkey *ecdsa.PublicKey) (ret Coordinate) {
	var X PubKeyAxis
	var Y PubKeyAxis

	err := X.Unmarshal(pubkey.X.Bytes())
	if err != nil {
		panic(err)
	}

	err = Y.Unmarshal(pubkey.Y.Bytes())
	if err != nil {
		panic(err)
	}

	copy(ret[:SizeAxis], X[:])
	copy(ret[SizeAxis:], Y[:])
	return
}

// Equal test if X,Y axis equals to a coordinates
func (c Coordinate) Equal(x1 PubKeyAxis, y1 PubKeyAxis) bool {
	if bytes.Equal(x1[:], c[:SizeAxis]) && bytes.Equal(y1[:], c[SizeAxis:]) {
		return true
	}
	return false
}

// Coordinate encodes X,Y into a coordinate
func (sp *SignedProto) Coordinate() (ret Coordinate) {
	copy(ret[:SizeAxis], sp.X[:])
	copy(ret[SizeAxis:], sp.Y[:])
	return
}

// Hash concats and hash as follows:
// blake2b(signPrefix + version + pubkey.X + pubkey.Y+len_32bit(msg) + message)
func (sp *SignedProto) Hash() []byte {
	hash, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	// write prefix
	_, err = hash.Write([]byte(SignaturePrefix))
	if err != nil {
		panic(err)
	}

	// write version
	err = binary.Write(hash, binary.LittleEndian, sp.Version)
	if err != nil {
		panic(err)
	}

	// write X & Y
	_, err = hash.Write(sp.X[:])
	if err != nil {
		panic(err)
	}

	_, err = hash.Write(sp.Y[:])
	if err != nil {
		panic(err)
	}

	// write message length
	err = binary.Write(hash, binary.LittleEndian, uint32(len(sp.Message)))
	if err != nil {
		panic(err)
	}

	// write message
	_, err = hash.Write(sp.Message)
	if err != nil {
		panic(err)
	}

	return hash.Sum(nil)
}

// Sign the message with a private key
func (sp *SignedProto) Sign(m *Message, privateKey *ecdsa.PrivateKey) {
	bts, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	// hash message
	sp.Version = ProtocolVersion
	sp.Message = bts

	err = sp.X.Unmarshal(privateKey.PublicKey.X.Bytes())
	if err != nil {
		panic(err)
	}
	err = sp.Y.Unmarshal(privateKey.PublicKey.Y.Bytes())
	if err != nil {
		panic(err)
	}
	hash := sp.Hash()

	// sign the message
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		panic(err)
	}
	sp.R = r.Bytes()
	sp.S = s.Bytes()
}

// Verify the signature of this signed message
func (sp *SignedProto) Verify() bool {
	var X, Y, R, S big.Int
	hash := sp.Hash()
	// verify against public key and r, s
	pubkey := ecdsa.PublicKey{}
	pubkey.Curve = DefaultCurve
	pubkey.X = &X
	pubkey.Y = &Y
	X.SetBytes(sp.X[:])
	Y.SetBytes(sp.Y[:])
	R.SetBytes(sp.R[:])
	S.SetBytes(sp.S[:])

	return ecdsa.Verify(&pubkey, hash, &R, &S)
}
