package parse

import (
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp/packet"
)

func (c *Context) parse(body io.Reader) error {
	oReader := packet.NewOpaqueReader(body)
	for {
		oPacket, err := oReader.Next()
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		packetSize := len(oPacket.Contents)
		packeType := "Old"
		if (oPacket.Contents[0] & 0x40) != 0 {
			packeType = "New"
		}
		packet, err := oPacket.Parse()
		if err != nil {
			return err
		}
		_ = packet
		c.Outputln(fmt.Sprintf("%s(%02x) Packet: Tag(%d) %d bytes", packeType, oPacket.Contents[0], oPacket.Tag, packetSize))

	}
	return nil
}
