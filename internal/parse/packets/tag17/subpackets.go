package tag17

import (
	"fmt"
	"strconv"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/sub"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

var parseSubpacketFunctions = sub.Functions{
	1: parseSPType01,
}

//ParseSub parsing Sub Packets
func ParseSub(sp *sub.Packets, pckt *items.Item) error {
	s := items.NewItem(sp.Title, "", "", "")
	for _, p := range sp.OpaqueSubpackets {
		if err := parseSubpacketFunctions.Get(int(p.SubType), sub.ParseSPReserved)(sp, p, s); err != nil {
			return err
		}
	}
	pckt.AddSub(s)
	return nil
}

//Image Attribute
func parseSPType01(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	length := values.Octets2IntLE(op.Contents[0:2])
	version := op.Contents[2]
	if version == 1 {
		st.AddSub(items.NewItem("Version", strconv.Itoa(int(version)), "", ""))
		enc := op.Contents[3]
		encName := "Unknown"
		if enc == 0x01 {
			encName = "JPEG"
		}
		st.AddSub(items.NewItem("Encoding", encName, fmt.Sprintf("(enc %d)", enc), ""))
	} else if 100 <= version && version <= 110 {
		st.AddSub(items.NewItem("Version", strconv.Itoa(int(version)), "private or experimental use", ""))
	} else {
		st.AddSub(items.NewItem("Version", strconv.Itoa(int(version)), "Unknown", ""))
	}
	st.AddSub(items.NewItem("Image data", "", fmt.Sprintf("%d bytes", len(op.Contents)-int(length)), ""))

	item.AddSub(st)
	return nil
}
