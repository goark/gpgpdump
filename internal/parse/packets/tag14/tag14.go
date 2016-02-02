package tag14

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/tag06"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag14 - Public-Subkey Packet
type Tag14 struct {
	*options.Options
	body []byte
}

//New return Tag14
func New(opt *options.Options, body []byte) *Tag14 {
	return &Tag14{Options: opt, body: body}
}

// Parse parsing Public-Subkey Packet
func (t Tag14) Parse(indent values.Indent) (values.Content, error) {
	return tag06.New(t.Options, t.body).Parse(indent) //redirect to Tag06
}
