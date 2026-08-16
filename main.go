package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	serverPort       = 8082
	heartbeatTimeout = 90 * time.Second
	maxEndpoints     = 10000
	cleanupInterval  = 60 * time.Second
	readBufferSize   = 65535
)

type endpoint struct {
	EndpointIP                   string       `json:"-"`
	EndpointUDPConnectionAddress *net.UDPAddr `json:"-"`
	LastSeen                     time.Time    `json:"-"`
}

type activeNetwork struct {
	NetworkID int                 `json:"-"`
	Endpoints map[int]endpoint    `json:"-"`
}

type clientRequest struct {
	NetworkID  json.Number `json:"networkID"`
	ClientID   json.Number `json:"clientID"`
	SrcIp      string      `json:"srcIp"`
	DstIp      string      `json:"dstIP"`
	PacketType string      `json:"packetType"`
	Payload    string      `json:"payload"`
}

// NetworkID returns the parsed network ID as an int.
func (r *clientRequest) NetworkIDInt() int {
	v, _ := r.NetworkID.Int64()
	return int(v)
}

// ClientID returns the parsed client ID as an int.
func (r *clientRequest) ClientIDInt() int {
	v, _ := r.ClientID.Int64()
	return int(v)
}

type controlResponse struct {
	PacketType string `json:"packetType"`
	Payload    string `json:"payload"`
}

var (
	activeNetworks map[int]activeNetwork
	mu             sync.RWMutex
	udpServer      *net.UDPConn
)

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func upsertEndpoint(networkID, clientID int, dstIP string, addr *net.UDPAddr) {
	mu.Lock()
	defer mu.Unlock()
	nw, ok := activeNetworks[networkID]
	if !ok {
		activeNetworks[networkID] = activeNetwork{
			NetworkID: networkID,
			Endpoints: map[int]endpoint{
				clientID: {
					EndpointIP:                   dstIP,
					EndpointUDPConnectionAddress: addr,
					LastSeen:                     time.Now(),
				},
			},
		}
		return
	}
	if len(nw.Endpoints) >= maxEndpoints {
		log.Printf("WARNING: network %d reached max endpoints (%d), evicting oldest", networkID, maxEndpoints)
		evictOldest(networkID)
	}
	nw.Endpoints[clientID] = endpoint{
		EndpointIP:                   dstIP,
		EndpointUDPConnectionAddress: addr,
		LastSeen:                     time.Now(),
	}
	activeNetworks[networkID] = nw
}

func evictOldest(networkID int) {
	nw, ok := activeNetworks[networkID]
	if !ok || len(nw.Endpoints) == 0 {
		return
	}
	var oldestID int
	var oldestTime time.Time
	first := true
	for id, ep := range nw.Endpoints {
		if first || ep.LastSeen.Before(oldestTime) {
			oldestID = id
			oldestTime = ep.LastSeen
			first = false
		}
	}
	delete(nw.Endpoints, oldestID)
	activeNetworks[networkID] = nw
}

func cleanupStaleEndpoints() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		mu.Lock()
		now := time.Now()
		for netID, nw := range activeNetworks {
			evicted := false
			for clientID, ep := range nw.Endpoints {
				if now.Sub(ep.LastSeen) > heartbeatTimeout {
					delete(nw.Endpoints, clientID)
					evicted = true
				}
			}
			if evicted {
				activeNetworks[netID] = nw
			}
			if len(nw.Endpoints) == 0 {
				delete(activeNetworks, netID)
			}
		}
		mu.Unlock()
	}
}

func forwardPacket(networkID int, dstIP, payload string) error {
	mu.RLock()
	nw, ok := activeNetworks[networkID]
	mu.RUnlock()
	if !ok {
		return fmt.Errorf("network %d not found", networkID)
	}
	body, err := json.Marshal(controlResponse{
		PacketType: "networkPacket",
		Payload:    payload,
	})
	if err != nil {
		return fmt.Errorf("marshal packet: %w", err)
	}
	mu.RLock()
	defer mu.RUnlock()
	for _, ep := range nw.Endpoints {
		if ep.EndpointIP == dstIP {
			_, err := udpServer.WriteToUDP(body, ep.EndpointUDPConnectionAddress)
			if err != nil {
				log.Printf("ERROR forwarding to %s: %v", dstIP, err)
			} else {
				log.Printf("FORWARDED packet to %s (network %d)", dstIP, networkID)
			}
			return nil
		}
	}
	logPrefix := fmt.Sprintf("[network %d] forwarding to %s", networkID, dstIP)
	log.Printf("%s: registered endpoints: ", logPrefix)
	for id, ep := range nw.Endpoints {
		log.Printf("  client %d -> %s (addr: %s)", id, ep.EndpointIP, ep.EndpointUDPConnectionAddress)
	}
	return fmt.Errorf("%s: destination not found", logPrefix)
}

func sendControlResponse(addr *net.UDPAddr, resp controlResponse) {
	body, err := json.Marshal(resp)
	if err != nil {
		log.Printf("ERROR marshaling control response: %v", err)
		return
	}
	_, err = udpServer.WriteToUDP(body, addr)
	if err != nil {
		log.Printf("ERROR sending control response: %v", err)
	}
}

func processClientRequest(req clientRequest, addr *net.UDPAddr) {
	// Always register/update the endpoint based on the sender's declared IP
	if req.SrcIp != "" {
		upsertEndpoint(req.NetworkIDInt(), req.ClientIDInt(), req.SrcIp, addr)
		log.Printf("Registered client %d (IP=%s) on network %d from %s", req.ClientIDInt(), req.SrcIp, req.NetworkIDInt(), addr)
	}

	if req.PacketType == "networkPacket" {
		if len(req.Payload) == 0 {
			log.Printf("WARNING: empty payload from client %d", req.ClientIDInt())
			return
		}
		cleanPayload, err := base64.StdEncoding.DecodeString(req.Payload)
		if err != nil {
			log.Printf("WARNING: base64 decode error from client %d: %v", req.ClientIDInt(), err)
		} else {
			log.Printf("Payload: %d bytes from client %d", len(cleanPayload), req.ClientIDInt())
			if len(cleanPayload) > 0 {
				log.Printf("First byte: %02x", cleanPayload[0])
			}
		}
		err = forwardPacket(req.NetworkIDInt(), req.DstIp, req.Payload)
		if err != nil {
			log.Printf("ERROR forwarding to %s on network %d: %v", req.DstIp, req.NetworkIDInt(), err)
		}
	} else if req.PacketType == "controlMessage" {
		sEnc := base64.StdEncoding.EncodeToString([]byte("ServerHello"))
		sendControlResponse(addr, controlResponse{
			PacketType: "controlMessage",
			Payload:    sEnc,
		})
		log.Printf("Control response sent to client %d", req.ClientIDInt())
	} else {
		log.Printf("WARNING: unknown packet type from client %d", req.ClientIDInt())
	}
}

func controlServer() {
	addr := net.UDPAddr{
		Port: serverPort,
		IP:   net.ParseIP("0.0.0.0"),
	}
	var err error
	udpServer, err = net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Failed to start UDP server on port %d: %v", serverPort, err)
	}
	defer udpServer.Close()
	log.Printf("UDP server listening on :%d", serverPort)
	buf := make([]byte, readBufferSize)
	for {
		n, remoteAddr, err := udpServer.ReadFromUDP(buf)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok {
				if opErr.Err.Error() == "use of closed network connection" {
					log.Println("UDP server shut down gracefully")
					return
				}
			}
			log.Printf("UDP read error: %v", err)
			continue
		}
		data := bytes.TrimRight(buf[:n], "\x00")
		if len(data) == 0 {
			continue
		}
		var req clientRequest
		if err := json.Unmarshal(data, &req); err != nil {
			log.Printf("WARNING: JSON unmarshal error from %s: %v", remoteAddr, err)
			continue
		}
		go processClientRequest(req, remoteAddr)
	}
}

func gracefulShutdown() {
	log.Println("Shutting down server...")
	if udpServer != nil {
		udpServer.Close()
	}
	log.Println("Server shut down complete")
}

func main() {
	activeNetworks = make(map[int]activeNetwork)
	go cleanupStaleEndpoints()
	go controlServer()
	log.Println("LinkServer started successfully")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	gracefulShutdown()
}
