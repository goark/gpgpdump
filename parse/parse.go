package parse

import (
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/packets"

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
		c.Outputln(packets.TagName(packeType, int(oPacket.Tag), packetSize, 0))
		_ = packet
	}
	return nil
}
