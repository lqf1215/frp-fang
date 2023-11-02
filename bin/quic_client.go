package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/quic-go/quic-go"
	"io"
	"time"
)

func main() {
	ctx := context.Background()
	//addr := "localhost:8888"
	addr := "192.168.10.42:56949"
	session, err := quic.DialAddr(ctx, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"frp"}}, &quic.Config{
		MaxIdleTimeout:     time.Duration(30) * time.Second,
		MaxIncomingStreams: int64(100000),
		KeepAlivePeriod:    time.Duration(10) * time.Second,
	})
	if err != nil {
		panic(err)
	}
	//defer session.Close()

	// 待发送的多条消息
	for i := 0; i < 10; i++ {

		stream, err := session.OpenStream()
		if err != nil {
			panic(err)
		}
		err = msg.WriteMsg(stream, &msg.P2pMessageVisitor{
			Content: fmt.Sprintf("Message %v", i),
			Sid:     fmt.Sprintf("sid - %v", i),
		})
		if err != nil {
			log.Error("[udp SendUdpMessage] WriteMsg err=%v", err)
		}
		// 将每条消息写入流
		//_, err = stream.Write([]byte(message))
		//if err != nil {
		//	log.Error("write error: %v", err)
		//}
		log.Warn("Sent: %s", i)
	}
	stream, err := session.OpenStream()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 1024)
	n, err := io.ReadFull(stream, buf)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Received message: %s\n", string(buf[:n]))
	for {
		handleSession1(ctx, session)
	}
}
func handleSessionWrite(ctx context.Context, session quic.Connection) {
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
		go handleStreamWrite(stream)
	}
}

func handleStreamWrite(stream quic.Stream) {
	defer stream.Close()
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		log.Error("Error reading from stream: %v", err)
		return
	}
	log.Warn("Received message: %s", string(buf[:n]))

	// 在这里添加发送消息的逻辑
	sendMsg := "Hello, client!"
	_, err = stream.Write([]byte(sendMsg))
	if err != nil {
		log.Error("Error writing to stream: %v", err)
		return
	}
	log.Warn("Sent message: %s", sendMsg)
}

func handleSession1(ctx context.Context, session quic.Connection) {
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
		go handleStream1(stream)
	}
}

func handleStream1(stream quic.Stream) {
	defer stream.Close()
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		log.Error("Error reading from stream: %v", err)
		return
	}
	log.Warn("Received message: %s", string(buf[:n]))
}
