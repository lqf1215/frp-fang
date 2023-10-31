package udp

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUdpPacket(t *testing.T) {
	assert := assert.New(t)

	buf := []byte("hello world")
	addr := &net.UDPAddr{
		IP:   net.IPv4(119, 120, 92, 239),
		Port: 60793,
		Zone: "",
	}
	udpMsg := NewUDPPacket(buf, addr, addr)

	newBuf, err := GetContent(udpMsg)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("udpMsg: %s\n", udpMsg)
	fmt.Printf("newBuf: %s\n", newBuf)
	assert.NoError(err)
	assert.EqualValues(buf, newBuf)
}
