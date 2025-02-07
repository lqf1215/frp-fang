// Copyright 2023 The frp Authors
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

package proxy

import (
	protoQuic "github.com/fatedier/frp/pkg/proto/quic"
	"io"
	"net"
	"reflect"
	"time"

	fmux "github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/nathole"
	"github.com/fatedier/frp/pkg/transport"
	utilnet "github.com/fatedier/frp/pkg/util/net"
)

func init() {
	RegisterProxyFactory(reflect.TypeOf(&v1.XTCPProxyConfig{}), NewXTCPProxy)
}

type XTCPProxy struct {
	*BaseProxy

	cfg *v1.XTCPProxyConfig
}

func NewXTCPProxy(baseProxy *BaseProxy, cfg v1.ProxyConfigurer) Proxy {
	unwrapped, ok := cfg.(*v1.XTCPProxyConfig)
	if !ok {
		return nil
	}
	return &XTCPProxy{
		BaseProxy: baseProxy,
		cfg:       unwrapped,
	}
}

func (pxy *XTCPProxy) InWorkConn(conn net.Conn, startWorkConnMsg *msg.StartWorkConn) {
	xl := pxy.xl
	defer conn.Close()
	var natHoleSidMsg msg.NatHoleSid
	err := msg.ReadMsgInto(conn, &natHoleSidMsg)
	if err != nil {
		xl.Error("[proxy xtcp] xtcp read from workConn error: %v", err)
		return
	}

	xl.Warn("[proxy xtcp] nathole prepare start NatHoleSTUNServer=[%+v] natHoleSidMsg=[%+v]", pxy.clientCfg.NatHoleSTUNServer, natHoleSidMsg)
	prepareResult, err := nathole.Prepare([]string{pxy.clientCfg.NatHoleSTUNServer})
	if err != nil {
		xl.Warn("[proxy xtcp] nathole prepare error: %v", err)
		return
	}
	xl.Info("[proxy xtcp] nathole prepare success, nat type: %s, behavior: %s, addresses: %v, assistedAddresses: %v",
		prepareResult.NatType, prepareResult.Behavior, prepareResult.Addrs, prepareResult.AssistedAddrs)
	defer prepareResult.ListenConn.Close()

	// send NatHoleClient msg to server
	transactionID := nathole.NewTransactionID()
	natHoleClientMsg := &msg.NatHoleClient{
		TransactionID: transactionID,
		ProxyName:     pxy.cfg.Name,
		Sid:           natHoleSidMsg.Sid,
		MappedAddrs:   prepareResult.Addrs,
		AssistedAddrs: prepareResult.AssistedAddrs,
	}

	xl.Warn("[proxy xtcp] nathole exchange info start")
	natHoleRespMsg, err := nathole.ExchangeInfo(pxy.ctx, pxy.msgTransporter, transactionID, natHoleClientMsg, 5*time.Second)
	if err != nil {
		xl.Warn("[proxy xtcp] nathole exchange info error: %v", err)
		return
	}

	xl.Info("[proxy xtcp] get natHoleRespMsg, sid [%s], protocol [%s], candidate address %v, assisted address %v, detectBehavior: %+v",
		natHoleRespMsg.Sid, natHoleRespMsg.Protocol, natHoleRespMsg.CandidateAddrs,
		natHoleRespMsg.AssistedAddrs, natHoleRespMsg.DetectBehavior)

	listenConn := prepareResult.ListenConn
	newListenConn, raddr, err := nathole.MakeHole(pxy.ctx, listenConn, natHoleRespMsg, []byte(pxy.cfg.Secretkey))
	if err != nil {
		listenConn.Close()
		xl.Warn("[proxy xtcp] make hole error: %v send msg sid [%s]", err, natHoleRespMsg.Sid)
		_ = pxy.msgTransporter.Send(&msg.NatHoleReport{
			Sid:     natHoleRespMsg.Sid,
			Success: false,
		})
		return
	}
	listenConn = newListenConn
	xl.Info("[proxy xtcp] establishing nat hole connection successful, sid [%s], remoteAddr [%s]", natHoleRespMsg.Sid, raddr)

	_ = pxy.msgTransporter.Send(&msg.NatHoleReport{
		Sid:     natHoleRespMsg.Sid,
		Success: true,
	})
	xl.Warn("[proxy xtcp] nathole exchange info send msg end sid [%s] success =true protocol=[%v]", natHoleRespMsg.Sid, natHoleRespMsg.Protocol)

	//go nathole.WaitDetectMsgMessage(pxy.ctx, listenConn, natHoleRespMsg.Sid, []byte(pxy.cfg.Secretkey))

	//xl.Warn("[proxy xtcp] xtcp WaitDetectMsgMessage end =[%v]", listenConn == nil)

	//n, err := udp.SendUdpMessage(listenConn, raddr, &msg.P2pMessageProxy{
	//	Content: "proxyhello",
	//	Sid:     natHoleRespMsg.Sid,
	//})
	//if err != nil {
	//	xl.Error("[proxy xtcp] xtcp send udp message error: %v", err)
	//}
	//xl.Warn("[proxy xtcp] xtcp send udp message success n=[%d] protocol=%v", n, natHoleRespMsg.Protocol)

	if natHoleRespMsg.Protocol == "kcp" {
		pxy.listenByKCP(listenConn, raddr, startWorkConnMsg)
		return
	}
	xl.Warn("[proxy xtcp] xtcp listen by quic start LocalAddr=[%+v] ", listenConn)
	// default is quic
	pxy.listenByQUIC(listenConn, raddr, startWorkConnMsg)
	xl.Warn("[proxy xtcp] xtcp listen by quic end LocalAddr=[%+v] ", listenConn)

}

func (pxy *XTCPProxy) listenByKCP(listenConn *net.UDPConn, raddr *net.UDPAddr, startWorkConnMsg *msg.StartWorkConn) {
	xl := pxy.xl
	xl.Warn("[proxy xtcp] xtcp listen by kcp listenByKCP start LocalAddr [%s]", listenConn.LocalAddr())
	listenConn.Close()
	laddr, _ := net.ResolveUDPAddr("udp", listenConn.LocalAddr().String())
	lConn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		xl.Warn("dial udp error: %v", err)
		return
	}
	defer lConn.Close()

	remote, err := utilnet.NewKCPConnFromUDP(lConn, true, raddr.String())
	if err != nil {
		xl.Warn("create kcp connection from udp connection error: %v", err)
		return
	}

	fmuxCfg := fmux.DefaultConfig()
	fmuxCfg.KeepAliveInterval = 10 * time.Second
	fmuxCfg.MaxStreamWindowSize = 6 * 1024 * 1024
	fmuxCfg.LogOutput = io.Discard
	session, err := fmux.Server(remote, fmuxCfg)
	if err != nil {
		xl.Error("create mux session error: %v", err)
		return
	}
	defer session.Close()

	for {
		muxConn, err := session.Accept()
		if err != nil {
			xl.Error("accept connection error: %v", err)
			return
		}
		xl.Warn("[proxy xtcp] xtcp listen by kcp HandleTCPWorkConnection start")
		go pxy.HandleTCPWorkConnection(muxConn, startWorkConnMsg, []byte(pxy.cfg.Secretkey))
		xl.Warn("[proxy xtcp] xtcp listen by kcp HandleTCPWorkConnection end")
	}
}

func (pxy *XTCPProxy) listenByQUIC(listenConn *net.UDPConn, _ *net.UDPAddr, startWorkConnMsg *msg.StartWorkConn) {
	xl := pxy.xl
	defer listenConn.Close()

	tlsConfig, err := transport.NewServerTLSConfig("", "", "")
	if err != nil {
		xl.Warn("create tls config error: %v", err)
		return
	}
	xl.Warn("[proxy xtcp] xtcp listen by quic listenByQUIC start LocalAddr [%s] RemoteAddr [%s] ", listenConn.LocalAddr(), listenConn.RemoteAddr())
	tlsConfig.NextProtos = []string{"frp"}
	quicListener, err := quic.Listen(listenConn, tlsConfig,
		&quic.Config{
			MaxIdleTimeout:     time.Duration(pxy.clientCfg.Transport.QUIC.MaxIdleTimeout) * time.Second,
			MaxIncomingStreams: int64(pxy.clientCfg.Transport.QUIC.MaxIncomingStreams),
			KeepAlivePeriod:    time.Duration(pxy.clientCfg.Transport.QUIC.KeepalivePeriod) * time.Second,
		},
	)
	xl.Warn("[proxy xtcp] xtcp listen by quic listenByQUIC quicListener end  [%s]  ", quicListener == nil)
	if err != nil {
		xl.Warn("[proxy xtcp] dial quic error: %v", err)
		return
	}
	// only accept one connection from raddr
	c, err := quicListener.Accept(pxy.ctx)
	if err != nil {
		xl.Error("quic accept connection error: %v", err)
		return
	}
	xl.Info("[proxy xtcp] xtcp listenByQUIC for to ")
	err = protoQuic.SendQuicOpenStream(c, &msg.P2pMessageVisitor{
		Content: "我是listenByQUIC proxy1111",
		Sid:     "hello 111",
	})

	err = protoQuic.SendQuicOpenStream(c, &msg.P2pMessageVisitor{
		Content: "我是listenByQUIC proxy2222",
		Sid:     "hello 222",
	})
	if err != nil {
		xl.Error("[proxy xtcp] quic send open stream message error: %v", err)
	}
	for {
		stream, err := c.AcceptStream(pxy.ctx)
		if err != nil {
			xl.Debug("quic accept stream error: %v", err)
			_ = c.CloseWithError(0, "")
			return
		}
		xl.Warn("[proxy xtcp] xtcp listen by kcp listenByQUIC start")
		go pxy.HandleTCPWorkConnection(utilnet.QuicStreamToNetConn(stream, c), startWorkConnMsg, []byte(pxy.cfg.Secretkey))

		xl.Warn("[proxy xtcp] xtcp listen by kcp HandleStream start")
		go protoQuic.HandleStream(stream)
		xl.Warn("[proxy xtcp] xtcp listen by kcp HandleStream end")

		protoQuic.SendQuicOpenStream(c, &msg.P2pMessageVisitor{
			Content: "我是listenByQUIC proxy3333",
			Sid:     "hello 333",
		})
	}

}
