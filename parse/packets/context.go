package packets

import (
	"fmt"
	"time"

	"golang.org/x/crypto/openpgp/packet"
)

// Indent is indent size
type Indent int

// Fill space
func (ind Indent) Fill(str string) string {
	return ind.String() + str
}

func (ind Indent) String() string {
	indStr := ""
	for i := 0; i < int(ind); i++ {
		indStr = indStr + "        "
	}
	return indStr
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

// UnixTime returns time string
func UnixTime(u uint32, utc bool) string {
	t := time.Unix(int64(u), 0)
	if utc {
		t = t.In(time.UTC)
	}
	return t.Format(time.RFC3339)
}

// Context for parsing packet
type Context struct {
	Hflag        bool                 //displays this help
	Vflag        bool                 //displays version
	Aflag        bool                 //accepts ASCII input only
	Gflag        bool                 //selects alternate dump format
	Iflag        bool                 //dumps integer packets
	Lflag        bool                 //dumps literal packets
	Mflag        bool                 //dumps marker packets
	Pflag        bool                 //dumps private packets
	Uflag        bool                 //displays UTC time
	OpaquePacket *packet.OpaquePacket // Opaque Packet
}

// PacketName returns packet name
func (cxt *Context) PacketName() string {
	tag := int(cxt.OpaquePacket.Tag)
	firstByte := FirstByte(cxt.OpaquePacket.Contents[0])
	size := len(cxt.OpaquePacket.Contents)
	return fmt.Sprintf("%v: %s (tag %d)(%d bytes)", firstByte, GetTagname(tag), tag, size)
}

// Parse packet
func (cxt *Context) Parse() (packet.Packet, error) {
	return cxt.OpaquePacket.Parse()
}
