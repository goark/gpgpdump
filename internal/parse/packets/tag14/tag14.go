package tag14

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag06"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
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
func (t Tag14) Parse(indent values.Indent) (values.Content, error) {
	return tag06.New(t.Options, t.tag, t.body).Parse(indent) //redirect to Tag06
}
