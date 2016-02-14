package tag19

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag19 - Modification Detection Code Packet
type Tag19 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Modification Detection Code Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag19 {
	return &Tag19{Options: opt, tag: tag, body: body}
}

// Parse parsing Modification Detection Code Packet
func (t *Tag19) Parse() (*items.Item, error) {
	pckt := t.tag.Get(len(t.body))
	pckt.AddSub(items.NewItem("MDC", "", "SHA-1 (20 bytes)", ""))
	return pckt, nil
}
