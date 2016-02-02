package unknown

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Unknown - Unknown Packet
type Unknown struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Unknown Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Unknown {
	return &Unknown{Options: opt, tag: tag, body: body}
}

// Parse parsing Unknown Packet
func (t Unknown) Parse() (*items.Item, error) {
	return t.tag.Get(len(t.body)), nil
}
