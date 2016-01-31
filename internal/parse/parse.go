package parse

import (
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"

	"golang.org/x/crypto/openpgp/armor"
)

func parseArmor(opt *options.Options, reader io.Reader) (values.Content, error) {
	block, err := armor.Decode(reader)
	if err != nil {
		return nil, err
	}
	return parse(opt, block.Body)
}

func parseBinary(opt *options.Options, reader io.Reader) (values.Content, error) {
	return parse(opt, reader)
}

func parse(opt *options.Options, body io.Reader) (values.Content, error) {
	pckts := packets.NewPackets(body)
	content := values.NewContent()
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
		content = append(content, c...)
	}
	return content, nil
}
