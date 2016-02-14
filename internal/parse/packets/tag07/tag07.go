package tag07

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag05"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag07 - Secret-Subkey Packet
type Tag07 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Secret-Subkey Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag07 {
	return &Tag07{Options: opt, tag: tag, body: body}
}

// Parse parsing Secret-Subkey Packet
func (t *Tag07) Parse() (*items.Item, error) {
	return tag05.New(t.Options, t.tag, t.body).Parse() //redirect to Tag05
}
