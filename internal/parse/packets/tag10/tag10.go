package tag10

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag10 - Marker Packet (Obsolete Literal Packet)
type Tag10 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Marker Packet (Obsolete Literal Packet)
func New(opt *options.Options, tag values.Tag, body []byte) *Tag10 {
	return &Tag10{Options: opt, tag: tag, body: body}
}

// Parse parsing Marker Packet (Obsolete Literal Packet)
func (t *Tag10) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))
	pckt.AddSub(values.LiteralData(t.body, t.Mflag).Get())
	return pckt, nil
}
