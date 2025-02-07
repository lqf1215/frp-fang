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
	"context"
	"encoding/base64"
	"github.com/fatedier/frp/pkg/nathole"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/xlog"
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

func ReadFromUDP(ctx context.Context, conn *net.UDPConn) {
	xl := xlog.FromContextSafe(ctx)

	xl.Warn("[udp ReadFromUDP]start", conn.LocalAddr())
	if conn == nil {
		xl.Error("[udp ReadFromUDP]conn is nil")
		return
	}

	for {
		buf := make([]byte, 1024)
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			xl.Error("[udp ReadFromUDP]ReadFromUDP error: %v", err)
			return
		}
		// buf[:n] will be encoded to string, so the bytes can be reused
		xl.Info("[udp ReadFromUDP]= buf:%v addr:%v count:%v\n", string(buf[:n]), remoteAddr, n)

		var m2 msg.Message
		err = nathole.DecodeMessageInto(buf, []byte("abcdefg"), &m2)
		if err != nil {
			xl.Error("[ReadFromUDP] decode sid message error: %v", err)
			continue
		}
		xl.Warn("[ReadFromUDP] DecodeMessageInto send sid message end m2 [%+v] ", m2)
		//xl.Info("[udp ReadFromUDP]Received UDP data from %s: %+v\n", remoteAddr, m)
		//var data msg.Message
		//if err := json.Unmarshal(buf[:n], &data); err != nil {
		//	xl.Error("Error unmarshaling JSON: %v\n", err)
		//	continue
		//}
		//switch d := data.(type) {
		//case msg.P2pMessageVisitor:
		//	xl.Warn("[udp ReadFromUDP]P2pMessageVisitor Received UDP data from %s: %+v\n", remoteAddr, d)
		//case msg.P2pMessageProxy:
		//	xl.Warn("[udp ReadFromUDP]P2pMessageProxy Received UDP data from %s: %+v\n", remoteAddr, d)
		//default:
		//	xl.Warn("[udp ReadFromUDP]Received UDP data from %s: %+v\n", remoteAddr, d)
		//}

	}

}

func SendUdpMessage(conn *net.UDPConn, raddr *net.UDPAddr, message msg.Message) (int, error) {

	buf, err := nathole.EncodeMessage(message, []byte("abcdefg"))
	n, err := conn.WriteToUDP(buf, raddr)

	if err != nil {
		return 0, err
	}

	log.Warn("[udp SendUdpMessage] n=%d, raddr=[%v]", n, raddr.String())

	return n, nil
}
