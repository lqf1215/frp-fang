// Copyright 2017 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package udp

import (
	"encoding/base64"
	"encoding/json"
	"github.com/fatedier/frp/pkg/util/log"
	"net"
	"sync"
	"time"

	"github.com/fatedier/golib/errors"
	"github.com/fatedier/golib/pool"

	"github.com/fatedier/frp/pkg/msg"
)

func NewUDPPacket(buf []byte, laddr, raddr *net.UDPAddr) *msg.UDPPacket {
	return &msg.UDPPacket{
		Content:    base64.StdEncoding.EncodeToString(buf),
		LocalAddr:  laddr,
		RemoteAddr: raddr,
	}
}

func GetContent(m *msg.UDPPacket) (buf []byte, err error) {
	buf, err = base64.StdEncoding.DecodeString(m.Content)
	return
}

func ForwardUserConn(udpConn *net.UDPConn, readCh <-chan *msg.UDPPacket, sendCh chan<- *msg.UDPPacket, bufSize int) {
	// read
	go func() {
		for udpMsg := range readCh {
			buf, err := GetContent(udpMsg)
			if err != nil {
				continue
			}
			_, _ = udpConn.WriteToUDP(buf, udpMsg.RemoteAddr)
		}
	}()

	// write
	buf := pool.GetBuf(bufSize)
	defer pool.PutBuf(buf)
	for {
		n, remoteAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// buf[:n] will be encoded to string, so the bytes can be reused
		udpMsg := NewUDPPacket(buf[:n], nil, remoteAddr)

		select {
		case sendCh <- udpMsg:
		default:
		}
	}
}

func Forwarder(dstAddr *net.UDPAddr, readCh <-chan *msg.UDPPacket, sendCh chan<- msg.Message, bufSize int) {
	var mu sync.RWMutex
	udpConnMap := make(map[string]*net.UDPConn)

	// read from dstAddr and write to sendCh
	writerFn := func(raddr *net.UDPAddr, udpConn *net.UDPConn) {
		addr := raddr.String()
		defer func() {
			mu.Lock()
			delete(udpConnMap, addr)
			mu.Unlock()
			udpConn.Close()
		}()

		buf := pool.GetBuf(bufSize)
		for {
			_ = udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, _, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			udpMsg := NewUDPPacket(buf[:n], nil, raddr)
			if err = errors.PanicToError(func() {
				select {
				case sendCh <- udpMsg:
				default:
				}
			}); err != nil {
				return
			}
		}
	}

	// read from readCh
	go func() {
		for udpMsg := range readCh {
			buf, err := GetContent(udpMsg)
			if err != nil {
				continue
			}
			mu.Lock()
			udpConn, ok := udpConnMap[udpMsg.RemoteAddr.String()]
			if !ok {
				udpConn, err = net.DialUDP("udp", nil, dstAddr)
				if err != nil {
					mu.Unlock()
					continue
				}
				udpConnMap[udpMsg.RemoteAddr.String()] = udpConn
			}
			mu.Unlock()

			_, err = udpConn.Write(buf)
			if err != nil {
				udpConn.Close()
			}

			if !ok {
				go writerFn(udpMsg.RemoteAddr, udpConn)
			}
		}
	}()
}

type UDPServer struct {
	conn   *net.UDPConn
	buffer []byte
}

func ReadFromUDP(conn *net.UDPConn) {
	log.Warn("[udp ReadFromUDP]start", conn.LocalAddr())
	if conn == nil {
		log.Error("[udp ReadFromUDP]conn is nil")
		return
	}
	var buffer [1028]byte
	for {
		n, addr, err := conn.ReadFromUDP(buffer[:])
		if err != nil {
			log.Error("[udp ReadFromUDP]Error reading from UDP connection: %v\n", err)
			continue
		}
		if n == 0 {
			continue
		}

		log.Warn("[udp ReadFromUDP] addr=%s, n=%d, err=%v", addr, n)
		var data msg.Message
		if err := json.Unmarshal(buffer[:n], &data); err != nil {
			log.Error("Error unmarshaling JSON: %v\n", err)
			continue
		}
		switch data.(type) {
		case msg.P2pMessageVisitor:
			log.Warn("[udp ReadFromUDP]P2pMessageVisitor Received UDP data from %s: %+v\n", addr, data)
		case msg.P2pMessageProxy:
			log.Warn("[udp ReadFromUDP]P2pMessageProxy Received UDP data from %s: %+v\n", addr, data)
		default:
			log.Warn("[udp ReadFromUDP]Received UDP data from %s: %+v\n", addr, data)
		}

	}
}

func SendUdpMessage(conn *net.UDPConn, raddr *net.UDPAddr, message msg.Message) (int, error) {
	//err := msg.WriteMsg(conn, &message)
	marshal, err := json.Marshal(&message)
	if err != nil {
		return 0, err
	}
	n, err := conn.WriteToUDP(marshal, raddr)

	if err != nil {
		return 0, err
	}

	log.Warn("[udp SendUdpMessage] n=%d, raddr=%v", n, raddr.String())

	return n, nil
}
