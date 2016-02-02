package tag14

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag06"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Tag14 - Public-Subkey Packet
type Tag14 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Public-Subkey Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag14 {
	return &Tag14{Options: opt, tag: tag, body: body}
}

// Parse parsing Public-Subkey Packet
func (t Tag14) Parse() (*items.Item, error) {
	return tag06.New(t.Options, t.tag, t.body).Parse() //redirect to Tag06
}
