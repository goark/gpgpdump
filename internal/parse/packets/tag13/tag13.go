package tag13

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag13 - User ID Packet
type Tag13 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return User ID Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag13 {
	return &Tag13{Options: opt, tag: tag, body: body}
}

// Parse parsing User ID Packet
func (t Tag13) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))
	pckt.AddSub(items.NewItem("User ID", string(t.body), "", ""))
	return pckt, nil
}
