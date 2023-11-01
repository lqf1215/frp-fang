package quic

import (
	"context"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/quic-go/quic-go"
	"net"
	"time"
)

func GetQuicListenConn(ctx context.Context, listenConn *net.UDPConn) (quic.Connection, error) {
	xl := xlog.FromContextSafe(ctx)
	xl.Info("[GetQuicConn]   来了")
	tlsConfig, err := transport.NewServerTLSConfig("", "", "")
	if err != nil {
		xl.Warn("[GetQuicListen]  create tls config error: %v", err)
		return nil, err
	}
	xl.Info("[GetQuicConn]  local=[%v]  RemoteAddr=[%v] ", listenConn.LocalAddr(), listenConn.RemoteAddr())
	tlsConfig.NextProtos = []string{"frp"}
	quicListener, err := quic.Listen(listenConn, tlsConfig,
		&quic.Config{
			MaxIdleTimeout:     time.Duration(30) * time.Second,
			MaxIncomingStreams: int64(100000),
			KeepAlivePeriod:    time.Duration(10) * time.Second,
		},
	)
	if err != nil {
		xl.Warn("[GetQuicListen]  dial quic error: %v", err)
		return nil, err
	}
	c, err := quicListener.Accept(ctx)
	if err != nil {
		xl.Error("[ReadFromConnListenQuic] quic accept connection error: %v", err)
		return nil, err
	}
	return c, nil
}

func ReadFromConnListenQuic(ctx context.Context, quicConn quic.Connection) {
	xl := xlog.FromContextSafe(ctx)
	xl.Info("[ReadFromConnListenQuic] for来了")
	for {
		go handleSession(ctx, quicConn)
	}

}

func ReadFromQuic(ctx context.Context, stream quic.Stream) {
	//xl := xlog.FromContextSafe(ctx)
	log.Warn("[quic] ReadFromQuic 来了")
	for {
		go handleStream(stream)
	}

}

func handleSession(ctx context.Context, session quic.Connection) {
	defer func(session quic.Connection, code quic.ApplicationErrorCode, s string) {
		err := session.CloseWithError(code, s)
		if err != nil {
			log.Error("Error closing session: %v", err)
		}
	}(session, 0, "")

	for {
		stream, err := session.AcceptStream(ctx)

		if err != nil {
			log.Error("Error accepting stream: %v", err)
			stream.Close()
			return
		}
		go handleStream(stream)
	}

}

func handleStream(stream quic.Stream) {
	defer stream.Close()
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		log.Error("[quic handleStream]  Error reading from stream: %v", err)
		defer stream.Close()
		return
	}

	log.Warn("[quic handleStream]  Received message: %v", string(buf[:n]))

	readMsg, err := msg.ReadMsg(stream)
	if err != nil {
		log.Error("read error: %v", err)
		return
	}
	log.Warn("[quic handleStream] read message: %+v", readMsg)
}

func SendQuicOpenStream(session quic.Connection, message msg.Message) error {
	stream, err := session.OpenStream()
	if err != nil {
		log.Error("write error: %v", err)
		return err
	}
	log.Warn("[quic SendQuicOpenStream] send message: %+v", message)
	// 将每条消息写入流
	err = msg.WriteMsg(stream, message)
	if err != nil {
		log.Error("write error: %v", err)
	}
	return nil
}
