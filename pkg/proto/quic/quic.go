package quic

import (
	"context"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/quic-go/quic-go"
	"io"
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

func ReadFromQuic(ctx context.Context, stream quic.Stream) {
	//xl := xlog.FromContextSafe(ctx)
	log.Warn("[quic] ReadFromQuic 来了")
	for {
		go HandleStream(stream)
	}

}

func HandleSession(ctx context.Context, session quic.Connection) {
	xl := xlog.FromContextSafe(ctx)
	defer func(session quic.Connection, code quic.ApplicationErrorCode, s string) {
		err := session.CloseWithError(code, s)
		if err != nil {
			xl.Error("Error closing session: %v", err)
			return
		}
	}(session, 0, "")
	xl.Warn("[quic handleSession] 来了")

	for {
		stream, err := session.AcceptStream(ctx)

		if err != nil {
			xl.Error("Error accepting stream: %v", err)

			return
		}
		go HandleStream(stream)

	}

}

func HandleStream(stream quic.Stream) {
	log.Warn("[quic handleStream] 来了")
	defer stream.Close()
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		if err == io.EOF {
			// 流已关闭
			log.Warn("[quic handleStream] Stream closed.")
		} else {
			log.Error("[quic handleStream] Error reading from stream: %v", err)
		}
		return
	}

	log.Warn("[quic handleStream]  Received message: %v", string(buf[:n]))

	readMsg, err := msg.ReadMsg(stream)
	if err != nil {
		log.Error("read error: %v", err)
		return
	}
	switch m := readMsg.(type) {
	case *msg.P2pMessageVisitor:
		log.Warn("[quic handleStream] P2pMessageVisitor read message: 【%+v】", m)

	case *msg.P2pMessageProxy:
		log.Warn("[quic handleStream] P2pMessageProxy read message: 【%+v】", m)
	default:
		log.Warn("[quic handleStream] default read message: 【%+v】", m)

	}
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
