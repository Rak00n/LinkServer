package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const MaxWorkers = 1024

var workerSem = make(chan struct{}, MaxWorkers)

type endpoint struct {
	endpointIP                   string
	endpointUDPConnectionAddress *net.UDPAddr
}

type activeNetwork struct {
	networkID         int
	mu                sync.RWMutex
	endpointsByIP     map[string]int
	endpointsByClient map[int]int
	endpoints         []endpoint
}

var (
	activeNetworks   = make(map[int]*activeNetwork)
	activeNetworksMu sync.RWMutex
)

func getOrCreateNetwork(networkID int) *activeNetwork {
	activeNetworksMu.RLock()
	network, ok := activeNetworks[networkID]
	activeNetworksMu.RUnlock()
	if ok {
		return network
	}
	activeNetworksMu.Lock()
	defer activeNetworksMu.Unlock()
	network, ok = activeNetworks[networkID]
	if ok {
		return network
	}
	network = &activeNetwork{
		networkID:         networkID,
		endpointsByIP:     make(map[string]int),
		endpointsByClient: make(map[int]int),
		endpoints:         make([]endpoint, 0, 16),
	}
	activeNetworks[networkID] = network
	return network
}

func updateEndpoint(network *activeNetwork, clientID int, ip string, addr *net.UDPAddr) {
	network.mu.Lock()
	defer network.mu.Unlock()
	if existingIdx, ok := network.endpointsByClient[clientID]; ok {
		oldIP := network.endpoints[existingIdx].endpointIP
		network.endpoints[existingIdx] = endpoint{
			endpointIP:                   ip,
			endpointUDPConnectionAddress: addr,
		}
		delete(network.endpointsByIP, oldIP)
		network.endpointsByIP[ip] = existingIdx
	} else {
		idx := len(network.endpoints)
		network.endpoints = append(network.endpoints, endpoint{
			endpointIP:                   ip,
			endpointUDPConnectionAddress: addr,
		})
		network.endpointsByClient[clientID] = idx
		network.endpointsByIP[ip] = idx
	}
}

func findEndpointByIP(network *activeNetwork, ip string) (*endpoint, bool) {
	network.mu.RLock()
	defer network.mu.RUnlock()
	if idx, ok := network.endpointsByIP[ip]; ok {
		return &network.endpoints[idx], true
	}
	return nil, false
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

var packetPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 65535)
		return &buf
	},
}

var responsePool = sync.Pool{
	New: func() interface{} {
		return &bytes.Buffer{}
	},
}

type clientRequest struct {
	Cookie     string `json:"cookie"`
	NetworkID  int    `json:"networkID"`
	ClientID   int    `json:"clientID"`
	SrcIp      string `json:"srcIp"`
	DstIp      string `json:"dstIP"`
	PacketType string `json:"packetType"`
	Payload    string `json:"payload"`
}

func processClientRequest(req clientRequest, conn *net.UDPConn, remoteAddr *net.UDPAddr) {
	defer func() {
		<-workerSem
	}()

	network := getOrCreateNetwork(req.NetworkID)
	updateEndpoint(network, req.ClientID, req.SrcIp, remoteAddr)

	if req.PacketType == "networkPacket" {
		_, err := base64.StdEncoding.DecodeString(req.Payload)
		if err != nil {
			return
		}

		dstEndpoint, found := findEndpointByIP(network, req.DstIp)
		if !found {
			return
		}

		respBuf := responsePool.Get().(*bytes.Buffer)
		respBuf.Reset()
		respBuf.WriteString(`{"packetType":"networkPacket","payload":"`)
		respBuf.WriteString(req.Payload)
		respBuf.WriteString(`"}`)
		body := respBuf.Bytes()

		_, err = conn.WriteToUDP(body, dstEndpoint.endpointUDPConnectionAddress)
		if err != nil {
			return
		}
		responsePool.Put(respBuf)

	} else if req.PacketType == "controlMessage" {
		sEnc := base64.StdEncoding.EncodeToString([]byte("ServerHello"))
		respBuf := responsePool.Get().(*bytes.Buffer)
		respBuf.Reset()
		respBuf.WriteString(`{"packetType":"controlMessage","payload":"`)
		respBuf.WriteString(sEnc)
		respBuf.WriteString(`"}`)
		body := respBuf.Bytes()

		_, err := conn.WriteToUDP(body, remoteAddr)
		if err != nil {
			return
		}
		responsePool.Put(respBuf)
	}
}

func controlServer() {
	addr := &net.UDPAddr{
		Port: 8082,
		IP:   net.ParseIP("0.0.0.0"),
	}

	ser, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(fmt.Sprintf("Failed to listen on UDP :8082: %v", err))
	}
	defer ser.Close()

	fmt.Println("SDN Control Server listening on :8082")

	for {
		bufPtr := packetPool.Get().(*[]byte)
		p := *bufPtr

		n, remoteAddr, err := ser.ReadFromUDP(p)
		if err != nil {
			packetPool.Put(bufPtr)
			continue
		}

		data := p[:n]

		var req clientRequest
		if err := json.Unmarshal(data, &req); err != nil {
			packetPool.Put(bufPtr)
			continue
		}

		if req.Cookie != "ItWillBeClientCookie" {
			packetPool.Put(bufPtr)
			continue
		}

		if len(req.Payload) > 0 && req.Payload[0] != 96 {
			workerSem <- struct{}{}
			remoteAddrCopy := *remoteAddr
			go processClientRequest(req, ser, &remoteAddrCopy)
		}

		packetPool.Put(bufPtr)
	}
}

var activeNetworksCounter atomic.Uint64

func main() {
	activeNetworks = make(map[int]*activeNetwork)
	go controlServer()
	fmt.Println("LinkServer SDN started. Press Ctrl+C to stop.")
	for {
		time.Sleep(10 * time.Second)
		_ = activeNetworksCounter.Add(1)
	}
}
