package tag08

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag08 - Compressed Data Packet
type Tag08 struct {
	*options.Options
	body []byte
}

//New return Tag08
func New(opt *options.Options, body []byte) *Tag08 {
	return &Tag08{Options: opt, body: body}
}

// Parse parsing Compressed Data Packet
func (t Tag08) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()

	comp := values.CompAlg(t.body[0])
	content = append(content, (indent + 1).Fill(comp.String()))
	content = append(content, (indent + 1).Fill("Compressed data"))
	return content, nil
}
