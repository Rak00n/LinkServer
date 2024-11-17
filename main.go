package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	//"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	//"os"
	"time"
)

type endpoint struct {
	endpointIP string
	endpointUDPConnection *net.UDPConn
	endpointUDPConnectionAddress *net.UDPAddr
}

type activeNetwork struct {
	networkID int
	endpoints map[int]endpoint
}

type clientRequest struct {
	NetworkID int      `json:"networkID"`
	ClientID int      `json:"clientID"`
	SrcIp string            `json:"srcIp"`
	DstIp string            `json:"dstIP"`
	PacketType string		`json:"packetType"`
	Payload string          `json:"payload"`
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func processClientRequest(req clientRequest, conn net.UDPConn, remoteAddr *net.UDPAddr) {

	_, ok := activeNetworks[req.NetworkID]
	if !ok {
		endpoints := make(map[int]endpoint)
		endpoints[req.ClientID] = endpoint{
			endpointIP:            req.SrcIp,
			endpointUDPConnection: &conn,
			endpointUDPConnectionAddress: remoteAddr,
		}
		activeNetworks[req.NetworkID] = activeNetwork{
			networkID: req.NetworkID,
			endpoints: endpoints,
		}
	} else {
		_, ok := activeNetworks[req.NetworkID].endpoints[req.ClientID]
		if !ok {
			activeNetworks[req.NetworkID].endpoints[req.ClientID] = endpoint{
				endpointIP:            req.SrcIp,
				endpointUDPConnection: &conn,
				endpointUDPConnectionAddress: remoteAddr,
			}
		} else {
			activeNetworks[req.NetworkID].endpoints[req.ClientID] = endpoint{
				endpointIP:            req.SrcIp,
				endpointUDPConnection: &conn,
				endpointUDPConnectionAddress: remoteAddr,
			}
		}
	}
	if req.PacketType == "networkPacket" {
		cleanPayload,_ := base64.StdEncoding.DecodeString(req.Payload)
		fmt.Println(cleanPayload)
		//fmt.Println(req.Payload[16],req.Payload[17],req.Payload[18],req.Payload[19])
		fmt.Println(fmt.Sprintf("%016x",cleanPayload[0]))
		//ip := []byte{cleanPayload[16],cleanPayload[17],cleanPayload[18],cleanPayload[19]}
		//v := int(big.NewInt(0).SetBytes(ip).Uint64())
		//fmt.Println(v)
		//dstIP := int2ip(uint32(v))
		dstIP := req.DstIp
		fmt.Println(dstIP)
		body := []byte(`{
		"packetType": "networkPacket",
		"payload": "`+req.Payload+`"}`)
		fmt.Println("Retransmitting packet")
		fmt.Println(activeNetworks)
		for _,endpoint := range activeNetworks[req.NetworkID].endpoints {
			fmt.Println(endpoint)
			if endpoint.endpointIP == dstIP {
				fmt.Println(endpoint)

				_, err := endpoint.endpointUDPConnection.WriteToUDP(body, endpoint.endpointUDPConnectionAddress)
				fmt.Println(err)
			}

		}
	} else if req.PacketType == "controlMessage" {
		fmt.Println("Recieved Control Packet")
		sEnc := base64.StdEncoding.EncodeToString([]byte("ServerHello"))

		body := []byte(`{
		"packetType": "controlMessage",
		"payload": "`+sEnc+`"}`)
		_, err := activeNetworks[req.NetworkID].endpoints[req.ClientID].endpointUDPConnection.WriteToUDP(body, remoteAddr)
		fmt.Println(err)
	}
}


func controlServer() {

	addr := net.UDPAddr{
		Port: 8082,
		IP: net.ParseIP("0.0.0.0"),
	}
	ser, _ := net.ListenUDP("udp", &addr)
	for {
		p := make([]byte, 65535)
		n,remoteaddr,err := ser.ReadFromUDP(p)
		p = bytes.Trim(p, "\x00")
		fmt.Println(n)
		//fmt.Printf("Read a message from %v %s \n", remoteaddr, p)
		fmt.Println("Read a message from", remoteaddr,ser)
		if err !=  nil {
			fmt.Printf("Some error  %v", err)
			continue
		}
		data := clientRequest{}
		err = json.Unmarshal(p, &data)
		fmt.Println(data, err)
		if data.Payload[0] != 96 {
			go processClientRequest(data,*ser,remoteaddr)
		}


		//go sendResponse(ser, remoteaddr)
	}
}

var activeNetworks map[int]activeNetwork

func main() {
	activeNetworks = make(map[int]activeNetwork)
	//xorKey = []byte{0,1,2,3,4,5}
	go controlServer()
	for {
		time.Sleep(10 * time.Second)
	}
}
