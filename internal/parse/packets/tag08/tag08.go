package tag08

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag08 - Compressed Data Packet
type Tag08 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Compressed Data Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag08 {
	return &Tag08{Options: opt, tag: tag, body: body}
}

// Parse parsing Compressed Data Packet
func (t Tag08) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))

	comp := values.CompAlg(t.body[0])
	pckt.AddSub(comp.Get())
	pckt.AddSub(items.NewItem("Compressed data", "", ""))
	return pckt, nil
}
