package parse

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp/packet"
)

// Indent is indent size
type Indent int

// Fill space for Indent
func (ind Indent) Fill(str string) string {
	return ind.String() + str
}

func (ind Indent) String() string {
	if ind <= 0 {
		return ""
	}
	return strings.Repeat("\t", int(ind))
}

// FirstByte is first byte of packet
type FirstByte byte

// IsNew returns true if new type
func (fb FirstByte) IsNew() bool {
	return (fb & 0x40) != 0x00
}

func (fb FirstByte) String() string {
	if fb.IsNew() {
		return "New"
	}
	return "Old"
}

// StringPacketInfo returns string of packet information
func StringPacketInfo(oPacket *packet.OpaquePacket) string {
	tag := int(oPacket.Tag)
	firstByte := FirstByte(oPacket.Contents[0])
	size := len(oPacket.Contents)
	return fmt.Sprintf("%v: %s (tag %d)(%d bytes)", firstByte, tagnames.Get(tag), tag, size)
}

// StringRFC3339 returns time string from UNIX Time
func StringRFC3339(u uint32, utc bool) string {
	t := time.Unix(int64(u), 0)
	if utc {
		t = t.In(time.UTC)
	}
	return t.Format(time.RFC3339)
}
