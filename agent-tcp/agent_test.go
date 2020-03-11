package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/xtaci/bdls/consensus"
	"github.com/xtaci/bdls/crypto/blake2b"
	"github.com/xtaci/bdls/crypto/secp256k1"
)

const (
	numNodes = 20
)

func TestFullParticipant(t *testing.T) {
	curve := secp256k1.S256()
	var agents []*Agent
	var privateKeys []*ecdsa.PrivateKey
	var publicKeys []*ecdsa.PublicKey

	// initial data
	initialData := make([]byte, 1024)
	io.ReadFull(rand.Reader, initialData)
	t.Log("initial data hash for each participant", blake2b.Sum256(initialData))

	// generate keys
	for i := 0; i < numNodes; i++ {
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		assert.Nil(t, err)

		privateKeys = append(privateKeys, privateKey)
		publicKeys = append(publicKeys, &privateKey.PublicKey)
	}

	// initiated agents
	for i := 0; i < numNodes; i++ {
		tcpaddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
		assert.Nil(t, err)

		l, err := net.ListenTCP("tcp", tcpaddr)
		assert.Nil(t, err)

		// initiate config
		config := new(consensus.Config)
		config.Epoch = time.Now()
		config.CurrentState = initialData
		config.CurrentHeight = 0
		config.Participants = publicKeys
		config.PrivateKey = privateKeys[i]
		config.StateCompare = func(a consensus.State, b consensus.State) int { return bytes.Compare(a, b) }
		config.StateValidate = func(consensus.State) bool { return true }

		agent, err := NewAgent(l, config)
		assert.Nil(t, err)
		agents = append(agents, agent)
	}

	// connect agents
	numConn := 0
	for i := 0; i < numNodes; i++ {
		addr := agents[i].listener.Addr().String()
		for j := i + 1; j < numNodes; j++ {
			conn, err := net.Dial("tcp", addr)
			assert.Nil(t, err)
			err = agents[j].AddPeer(conn.(*net.TCPConn))
			assert.Nil(t, err)
			numConn++
		}
	}
	t.Log(numConn, "connection(s) established for", numNodes, "peers")
	t.Log("begining consensus")

	var wg sync.WaitGroup
	wg.Add(numNodes)

	stopHeight := uint64(5)
	for k := range agents {
		go func(i int) {
			agent := agents[i]
			defer wg.Done()
			for {
				data := make([]byte, 1024)
				io.ReadFull(rand.Reader, data)
				agent.Propose(data)

				// wait until next height
				confirmedStates, err := agent.Wait()
				assert.Nil(t, err)

				for _, cs := range confirmedStates {
					h := consensus.DefaultHash(cs.State)
					t.Logf("%v participants %3d <decide> at height: %v round:%v hash:%v", time.Now().Format("15:04:05"), i, cs.Height, cs.Round, hex.EncodeToString(h[:]))
					if cs.Height >= stopHeight {
						return
					}
				}
			}
		}(k)
	}

	wg.Wait()

	// keep agents alive to exchange decide messages
	// or agent will be GCed
	for k := range agents {
		runtime.KeepAlive(agents[k])
	}

	t.Logf("test stopped at height:%v as expected", stopHeight)
}
