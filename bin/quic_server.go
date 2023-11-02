package main

import (
	"context"
	"fmt"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/quic-go/quic-go"
)

//func main() {
//	ctx := context.Background()
//	addr := "localhost:8888"
//
//	tlsConfig, err := transport.NewServerTLSConfig("", "", "")
//	if err != nil {
//		log.Warn("create tls config error: %v", err)
//		panic(err)
//	}
//	tlsConfig.NextProtos = []string{"frp"}
//	listener, err := quic.ListenAddr(addr, tlsConfig, nil)
//	if err != nil {
//		panic(err)
//	}
//	defer listener.Close()
//	fmt.Println("Listening on ", addr, listener.Addr().String())
//	for {
//		session, err := listener.Accept(ctx)
//		if err != nil {
//			panic(err)
//		}
//		fmt.Println("Accept session ", session.RemoteAddr())
//		go handleSession(ctx, session)
//	}
//}

func main() {
	ctx := context.Background()
	addr := "localhost:8888"

	tlsConfig, err := transport.NewServerTLSConfig("", "", "")
	if err != nil {
		log.Warn("create tls config error: %v", err)
		panic(err)
	}
	tlsConfig.NextProtos = []string{"frp"}
	listener, err := quic.ListenAddr(addr, tlsConfig, nil)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Println("Listening on ", addr, listener.Addr().String())

	for {
		session, err := listener.Accept(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Println("Accept session ", session.RemoteAddr())
		go handleSession(ctx, session)

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
		log.Error("Error reading from stream: %v", err)
		return
	}

	log.Warn("Received message: %s", string(buf[:n]))
}
