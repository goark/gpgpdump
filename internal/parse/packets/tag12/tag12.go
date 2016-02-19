package tag12

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag12 - Trust Packet
type Tag12 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Trust Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag12 {
	return &Tag12{Options: opt, tag: tag, body: body}
}

// Parse parsing Trust Packet
func (t *Tag12) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))
	pckt.AddSub(values.NewRawData("Trust", "", t.body, true).Get())
	return pckt, nil
}
