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

package visitor

import (
	"context"
	"errors"
	"fmt"
	"github.com/fatedier/frp/pkg/util/log"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	libio "github.com/fatedier/golib/io"
	fmux "github.com/hashicorp/yamux"
	quic "github.com/quic-go/quic-go"
	"golang.org/x/time/rate"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/nathole"
	protoQuic "github.com/fatedier/frp/pkg/proto/quic"
	"github.com/fatedier/frp/pkg/transport"
	utilnet "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/util"
	"github.com/fatedier/frp/pkg/util/xlog"
)

var ErrNoTunnelSession = errors.New("no tunnel session")

type XTCPVisitor struct {
	*BaseVisitor
	session       TunnelSession
	startTunnelCh chan struct{}
	retryLimiter  *rate.Limiter
	cancel        context.CancelFunc

	cfg *v1.XTCPVisitorConfig
}

func (sv *XTCPVisitor) Run() (err error) {
	sv.ctx, sv.cancel = context.WithCancel(sv.ctx)

	if sv.cfg.Protocol == "kcp" {
		sv.session = NewKCPTunnelSession()
	} else {
		sv.session = NewQUICTunnelSession(sv.clientCfg)
	}

	if sv.cfg.BindPort > 0 {
		fmt.Println("[visitor xtcp] sv.cfg.BindPort > 0", sv.cfg.BindPort)
		sv.l, err = net.Listen("tcp", net.JoinHostPort(sv.cfg.BindAddr, strconv.Itoa(sv.cfg.BindPort)))
		if err != nil {
			return
		}
		go sv.worker()
	}

	go sv.internalConnWorker()
	go sv.processTunnelStartEvents()
	if sv.cfg.KeepTunnelOpen {
		sv.retryLimiter = rate.NewLimiter(rate.Every(time.Hour/time.Duration(sv.cfg.MaxRetriesAnHour)), sv.cfg.MaxRetriesAnHour)
		go sv.keepTunnelOpenWorker()
	}
	return
}

func (sv *XTCPVisitor) Close() {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.BaseVisitor.Close()
	if sv.cancel != nil {
		sv.cancel()
	}
	if sv.session != nil {
		sv.session.Close()
	}
}

func (sv *XTCPVisitor) worker() {
	xl := xlog.FromContextSafe(sv.ctx)
	for {
		conn, err := sv.l.Accept()
		if err != nil {
			xl.Warn("xtcp local listener closed")
			return
		}
		xl.Warn("[visitor] worker handleConn start RemoteAddr [%v] LocalAddr [%v]", conn.RemoteAddr(), conn.LocalAddr())
		go sv.handleConn(conn)
	}
}

func (sv *XTCPVisitor) internalConnWorker() {
	xl := xlog.FromContextSafe(sv.ctx)
	for {
		conn, err := sv.internalLn.Accept()
		if err != nil {
			xl.Warn("xtcp internal listener closed")
			return
		}
		xl.Info("[visitor] internalConnWorker handleConn start")
		go sv.handleConn(conn)
	}
}

func (sv *XTCPVisitor) processTunnelStartEvents() {
	for {
		select {
		case <-sv.ctx.Done():
			return
		case <-sv.startTunnelCh:
			start := time.Now()
			sv.makeNatHole()
			duration := time.Since(start)
			// avoid too frequently
			if duration < 10*time.Second {
				time.Sleep(10*time.Second - duration)
			}
		}
	}
}

func (sv *XTCPVisitor) keepTunnelOpenWorker() {
	xl := xlog.FromContextSafe(sv.ctx)
	ticker := time.NewTicker(time.Duration(sv.cfg.MinRetryInterval) * time.Second)
	defer ticker.Stop()

	sv.startTunnelCh <- struct{}{}
	for {
		select {
		case <-sv.ctx.Done():
			return
		case <-ticker.C:
			xl.Error("keepTunnelOpenWorker try to check tunnel...")
			conn, err := sv.getTunnelConn()
			if err != nil {
				xl.Warn("keepTunnelOpenWorker get tunnel connection error: %v", err)
				_ = sv.retryLimiter.Wait(sv.ctx)
				continue
			}
			xl.Error("keepTunnelOpenWorker check success")
			if conn != nil {
				conn.Close()
			}
		}
	}
}

func (sv *XTCPVisitor) handleConn(userConn net.Conn) {
	xl := xlog.FromContextSafe(sv.ctx)
	isConnTrasfered := false
	defer func() {
		if !isConnTrasfered {
			userConn.Close()
		}
	}()

	xl.Error("[visitor xtcp] get a new xtcp user connection userConn=%v - %v", userConn.LocalAddr(), userConn.RemoteAddr())

	// Open a tunnel connection to the server. If there is already a successful hole-punching connection,
	// it will be reused. Otherwise, it will block and wait for a successful hole-punching connection until timeout.
	ctx := context.Background()
	if sv.cfg.FallbackTo != "" {
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(sv.cfg.FallbackTimeoutMs)*time.Millisecond)
		defer cancel()
		ctx = timeoutCtx
	}
	tunnelConn, err := sv.openTunnel(ctx)
	if err != nil {
		xl.Error("[visitor xtcp]  open tunnel error: %v", err)
		// no fallback, just return
		if sv.cfg.FallbackTo == "" {
			return
		}

		xl.Error("[visitor xtcp] try to transfer connection to FallbackTo: [%s]", sv.cfg.FallbackTo)
		if err := sv.helper.TransferConn(sv.cfg.FallbackTo, userConn); err != nil {
			xl.Error("[visitor xtcp] transfer connection to FallbackTo [%s] error: %v", sv.cfg.FallbackTo, err)
			return
		}
		isConnTrasfered = true
		return
	}
	xl.Warn("[visitor xtcp] handleConn tunnelConn cfg=[%+v] tunnelConn=%v  RemoteAddr=%v", sv.cfg, tunnelConn.LocalAddr(), tunnelConn.RemoteAddr())
	var muxConnRWCloser io.ReadWriteCloser = tunnelConn
	if sv.cfg.Transport.UseEncryption {
		muxConnRWCloser, err = libio.WithEncryption(muxConnRWCloser, []byte(sv.cfg.SecretKey))
		if err != nil {
			xl.Error("create encryption stream error: %v", err)
			return
		}
	}
	xl.Warn("[visitor] handleConn UseEncryption =[%+v] UseCompression=%v  RemoteAddr=%v", sv.cfg.Transport.UseEncryption, sv.cfg.Transport.UseEncryption, tunnelConn.RemoteAddr())
	if sv.cfg.Transport.UseCompression {
		var recycleFn func()
		muxConnRWCloser, recycleFn = libio.WithCompressionFromPool(muxConnRWCloser)
		defer recycleFn()
	}

	_, _, errs := libio.Join(userConn, muxConnRWCloser)
	xl.Warn("join connections closed")
	if len(errs) > 0 {
		xl.Error("join connections errors: %v", errs)
	}
}

// openTunnel will open a tunnel connection to the target server.
func (sv *XTCPVisitor) openTunnel(ctx context.Context) (conn net.Conn, err error) {
	xl := xlog.FromContextSafe(sv.ctx)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	timeoutC := time.After(20 * time.Second)
	immediateTrigger := make(chan struct{}, 1)
	defer close(immediateTrigger)
	immediateTrigger <- struct{}{}

	for {
		select {
		case <-sv.ctx.Done():
			return nil, sv.ctx.Err()
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-immediateTrigger:
			conn, err = sv.getTunnelConn()
		case <-ticker.C:
			conn, err = sv.getTunnelConn()
		case <-timeoutC:
			return nil, fmt.Errorf("open tunnel timeout")
		}

		if err != nil {
			if err != ErrNoTunnelSession {
				xl.Warn("get tunnel connection error: %v", err)
			}
			continue
		}
		return conn, nil
	}
}

func (sv *XTCPVisitor) getTunnelConn() (net.Conn, error) {
	conn, err := sv.session.OpenConn(sv.ctx)
	if err == nil {
		return conn, nil
	}
	sv.session.Close()

	select {
	case sv.startTunnelCh <- struct{}{}:
	default:
	}
	return nil, err
}

// 0. PreCheck
// 1. Prepare
// 2. ExchangeInfo
// 3. MakeNATHole
// 4. Create a tunnel session using an underlying UDP connection.
func (sv *XTCPVisitor) makeNatHole() {
	xl := xlog.FromContextSafe(sv.ctx)
	xl.Warn("[visitor xtcp] makeNatHole start")
	if err := nathole.PreCheck(sv.ctx, sv.helper.MsgTransporter(), sv.cfg.ServerName, 5*time.Second); err != nil {
		xl.Warn("nathole precheck error: %v", err)
		return
	}

	xl.Warn("[visitor xtcp] nathole prepare start with stun server: %s", sv.clientCfg.NatHoleSTUNServer)
	prepareResult, err := nathole.Prepare([]string{sv.clientCfg.NatHoleSTUNServer})
	if err != nil {
		xl.Warn("nathole prepare error: %v", err)
		return
	}
	xl.Info("[visitor xtcp] nathole prepare success, nat type: %s, behavior: %s, addresses: %v, assistedAddresses: %v",
		prepareResult.NatType, prepareResult.Behavior, prepareResult.Addrs, prepareResult.AssistedAddrs)

	listenConn := prepareResult.ListenConn

	// send NatHoleVisitor to server
	now := time.Now().Unix()
	transactionID := nathole.NewTransactionID()
	natHoleVisitorMsg := &msg.NatHoleVisitor{
		TransactionID: transactionID,
		ProxyName:     sv.cfg.ServerName,
		Protocol:      sv.cfg.Protocol,
		SignKey:       util.GetAuthKey(sv.cfg.SecretKey, now),
		Timestamp:     now,
		MappedAddrs:   prepareResult.Addrs,
		AssistedAddrs: prepareResult.AssistedAddrs,
	}

	xl.Warn("[visitor xtcp] nathole exchange info start")
	natHoleRespMsg, err := nathole.ExchangeInfo(sv.ctx, sv.helper.MsgTransporter(), transactionID, natHoleVisitorMsg, 5*time.Second)
	if err != nil {
		listenConn.Close()
		xl.Warn("[visitor xtcp] nathole exchange info error: %v", err)
		return
	}

	xl.Info("[visitor xtcp] get natHoleRespMsg, sid [%s], protocol [%s], candidate address %v, assisted address %v, detectBehavior: %+v",
		natHoleRespMsg.Sid, natHoleRespMsg.Protocol, natHoleRespMsg.CandidateAddrs,
		natHoleRespMsg.AssistedAddrs, natHoleRespMsg.DetectBehavior)

	newListenConn, raddr, err := nathole.MakeHole(sv.ctx, listenConn, natHoleRespMsg, []byte(sv.cfg.SecretKey))
	if err != nil {
		listenConn.Close()
		xl.Warn("[visitor xtcp] make hole error: %v", err)
		return
	}
	listenConn = newListenConn
	xl.Info("[visitor xtcp] establishing nat hole connection successful, sid [%s], remoteAddr [%s] ", natHoleRespMsg.Sid, raddr)
	xl.Info("[visitor xtcp] establishing nat hole connection successful,  newListenConn=[%s] [%s]", newListenConn == nil, listenConn == nil)
	if err := sv.session.Init(listenConn, raddr); err != nil {

		listenConn.Close()
		xl.Warn("[visitor xtcp] init tunnel session error: %v", err)
		return
	}
	xl.Warn("[visitor xtcp] makeNatHole  sv.session.Init end LocalAddr=[%+v] ", listenConn)

	//quicListenConn, err := protoQuic.GetQuicListenConn(sv.ctx, listenConn)
	//
	//if err != nil {
	//	xl.Error("[visitor xtcp] GetQuicListenConn get quic listen conn error: %v", err)
	//}
	//go udp.ReadFromUDP(sv.ctx, listenConn)
	//go nathole.WaitDetectMsgMessage(sv.ctx, listenConn, natHoleRespMsg.Sid, []byte(sv.cfg.SecretKey))
	//xl.Warn("[visitor xtcp]   nathole.WaitDetectMsgMessage end LocalAddr=[%+v] RemoteAddr=[%+v] ", listenConn.LocalAddr(), listenConn.RemoteAddr())
	if quicSession, ok := sv.session.(*QUICTunnelSession); ok {
		// sv.session is a QUICTunnelSession, you can access the quic.Connection
		quicConnection := quicSession.session
		// Now, you can use quicConnection as needed
		xl.Warn("[visitor xtcp] makeNatHole  quic.ReadFromConnListenQuic start")
		go protoQuic.ReadFromConnListenQuic(sv.ctx, quicConnection)
		xl.Warn("[visitor xtcp] makeNatHole  quic.ReadFromConnListenQuic end=[%v]")

		err = protoQuic.SendQuicOpenStream(quicConnection, &msg.P2pMessageVisitor{
			Content: "visitorhello",
			Sid:     natHoleRespMsg.Sid,
		})
		if err != nil {
			xl.Error("[visitor xtcp] xtcp send SendQuicOpenStream message error: %v", err)
		}
		xl.Warn("[visitor xtcp] xtcp send SendQuicOpenStream message success ok end")

	} else if kcpSession, ok := sv.session.(*KCPTunnelSession); ok {
		// sv.session is a KCPTunnelSession, you can access the fmux.Session
		fmuxSession := kcpSession.session
		// Now, you can use fmuxSession as needed
		fmt.Println(fmuxSession)
	} else {
		// Handle cases where sv.session is neither a QUICTunnelSession nor a KCPTunnelSession
		fmt.Println("Unknown session type")
	}

	//n, err := udp.SendUdpMessage(listenConn, raddr, &msg.P2pMessageVisitor{
	//	Content: "visitorhello",
	//	Sid:     natHoleRespMsg.Sid,
	//})
	//xl.Warn("[visitor xtcp]   udp.SendUdpMessage  n=[%v]", n)
	//if err != nil {
	//	xl.Error("[proxy xtcp] xtcp send udp message error: %v", err)
	//}

	xl.Warn("[visitor xtcp] xtcp send SendQuicOpenStream message success")

}

type TunnelSession interface {
	Init(listenConn *net.UDPConn, raddr *net.UDPAddr) error
	OpenConn(context.Context) (net.Conn, error)
	Close()
}

type KCPTunnelSession struct {
	session *fmux.Session
	lConn   *net.UDPConn
	mu      sync.RWMutex
}

func NewKCPTunnelSession() TunnelSession {
	return &KCPTunnelSession{}
}

func (ks *KCPTunnelSession) Init(listenConn *net.UDPConn, raddr *net.UDPAddr) error {
	listenConn.Close()
	laddr, _ := net.ResolveUDPAddr("udp", listenConn.LocalAddr().String())
	lConn, err := net.DialUDP("udp", laddr, raddr)
	log.Warn("[visitor xtcp] KCPTunnelSession laddr: %v LocalAddr=%v ", laddr, listenConn.LocalAddr())
	if err != nil {
		return fmt.Errorf("dial udp error: %v", err)
	}
	remote, err := utilnet.NewKCPConnFromUDP(lConn, true, raddr.String())
	if err != nil {
		return fmt.Errorf("create kcp connection from udp connection error: %v", err)
	}

	fmuxCfg := fmux.DefaultConfig()
	fmuxCfg.KeepAliveInterval = 10 * time.Second
	fmuxCfg.MaxStreamWindowSize = 6 * 1024 * 1024
	fmuxCfg.LogOutput = io.Discard
	session, err := fmux.Client(remote, fmuxCfg)
	if err != nil {
		remote.Close()
		return fmt.Errorf("initial client session error: %v", err)
	}
	log.Warn("[visitor xtcp] KCPTunnelSession session: %v", session)
	ks.mu.Lock()
	ks.session = session
	ks.lConn = lConn
	ks.mu.Unlock()
	return nil
}

func (ks *KCPTunnelSession) OpenConn(_ context.Context) (net.Conn, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	session := ks.session
	if session == nil {
		return nil, ErrNoTunnelSession
	}
	return session.Open()
}

func (ks *KCPTunnelSession) Close() {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.session != nil {
		_ = ks.session.Close()
		ks.session = nil
	}
	if ks.lConn != nil {
		_ = ks.lConn.Close()
		ks.lConn = nil
	}
}

type QUICTunnelSession struct {
	session    quic.Connection
	listenConn *net.UDPConn
	mu         sync.RWMutex

	clientCfg *v1.ClientCommonConfig
}

func NewQUICTunnelSession(clientCfg *v1.ClientCommonConfig) TunnelSession {
	return &QUICTunnelSession{
		clientCfg: clientCfg,
	}
}

func (qs *QUICTunnelSession) Init(listenConn *net.UDPConn, raddr *net.UDPAddr) error {
	log.Warn("[visitor xtcp] QUICTunnelSession Init listenConn:LocalAddr %v RemoteAddr %v  raddr=%v", listenConn.LocalAddr(), listenConn.RemoteAddr(), raddr.String())
	tlsConfig, err := transport.NewClientTLSConfig("", "", "", raddr.String())

	log.Warn("[visitor xtcp] QUICTunnelSession Init: tlsConfig=[%+v] Transport.QUIC=[%+v]", tlsConfig, qs.clientCfg.Transport.QUIC)
	if err != nil {
		return fmt.Errorf("create tls config error: %v", err)
	}
	tlsConfig.NextProtos = []string{"frp"}
	quicConn, err := quic.Dial(context.Background(), listenConn, raddr, tlsConfig,
		&quic.Config{
			MaxIdleTimeout:     time.Duration(qs.clientCfg.Transport.QUIC.MaxIdleTimeout) * time.Second,
			MaxIncomingStreams: int64(qs.clientCfg.Transport.QUIC.MaxIncomingStreams),
			KeepAlivePeriod:    time.Duration(qs.clientCfg.Transport.QUIC.KeepalivePeriod) * time.Second,
		})
	if err != nil {
		return fmt.Errorf("dial quic error: %v", err)
	}
	log.Warn("[visitor xtcp] Init session QUICTunnelSession quicConn: LocalAddr=[%v] RemoteAddr=[%v]", quicConn.LocalAddr(), quicConn.RemoteAddr())
	qs.mu.Lock()
	qs.session = quicConn
	qs.listenConn = listenConn
	qs.mu.Unlock()
	//err = quicConn.SendMessage([]byte("hello woshi visitor xtcp QUICTunnelSession"))
	//if err != nil {
	//	log.Error("[visitor xtcp] Init session QUICTunnelSession quicConn.SendMessage error: %v", err)
	//}
	err = protoQuic.SendQuicOpenStream(quicConn, &msg.P2pMessageVisitor{
		Content: "我是QUICTunnelSession的init visitor",
		Sid:     "hello",
	})
	if err != nil {
		log.Error("[visitor xtcp] Init session QUICTunnelSession quicConn.SendMessage error: %v", err)
	}
	log.Warn("[visitor xtcp] Init session QUICTunnelSession quicConn.SendMessage success")
	return nil
}

func (qs *QUICTunnelSession) OpenConn(ctx context.Context) (net.Conn, error) {
	qs.mu.RLock()
	defer qs.mu.RUnlock()
	session := qs.session
	if session == nil {
		return nil, ErrNoTunnelSession
	}
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return utilnet.QuicStreamToNetConn(stream, session), nil
}

func (qs *QUICTunnelSession) Close() {
	qs.mu.Lock()
	defer qs.mu.Unlock()
	if qs.session != nil {
		_ = qs.session.CloseWithError(0, "")
		qs.session = nil
	}
	if qs.listenConn != nil {
		_ = qs.listenConn.Close()
		qs.listenConn = nil
	}
}
