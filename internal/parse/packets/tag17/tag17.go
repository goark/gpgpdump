package tag17

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/sub"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag17 - User Attribute Packet
type Tag17 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return User Attribute Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag17 {
	return &Tag17{Options: opt, tag: tag, body: body}
}

// Parse parsingUser Attribute Packet
func (t *Tag17) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))
	sp, osps, err := sub.New(t.Options, "Subpacket", t.body)
	if err != nil {
		return pckt, err
	}
	if err := ParseSub(sp, osps, pckt); err != nil {
		return pckt, err
	}
	return pckt, nil
}
