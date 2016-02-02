package parse

import (
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets"
	"github.com/spiegel-im-spiegel/gpgpdump/items"

	"golang.org/x/crypto/openpgp/armor"
)

func parseArmor(opt *options.Options, reader io.Reader) (*items.Packets, error) {
	block, err := armor.Decode(reader)
	if err != nil {
		return nil, err
	}
	return parse(opt, block.Body)
}

func parseBinary(opt *options.Options, reader io.Reader) (*items.Packets, error) {
	return parse(opt, reader)
}

func parse(opt *options.Options, body io.Reader) (*items.Packets, error) {
	pckts := packets.NewPackets(body)
	content := items.NewPackets()
	opt.ResetSymAlgMode()
	for {
		p, err := pckts.Next()
		if err != nil {
			return content, err
		}
		if p == nil {
			break
		}
		c, err := p.Parse(opt)
		if err != nil {
			return content, err
		}
		content.AddPacket(c)
	}
	return content, nil
}
