package tag17

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag17 - User Attribute Packet
type Tag17 struct {
	*options.Options
	body []byte
}

//New return Tag17
func New(opt *options.Options, body []byte) *Tag17 {
	return &Tag17{Options: opt, body: body}
}

// Parse parsing Literal Data Packet
func (t Tag17) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()
	sp, err := NewSubpackets(t.Options, "Subpacket -", t.body)
	if err != nil {
		return content, err
	}
	content = content.Add(sp.Parse(indent + 1))
	return content, nil
}
