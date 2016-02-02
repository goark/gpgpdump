package tag12

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag12 - Trust Packet
type Tag12 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Trust Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Tag12 {
	return &Tag12{Options: opt, tag: tag, body: body}
}

// Parse parsing Trust Packet
func (t Tag12) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()
	content = append(content, (indent + 1).Fill(fmt.Sprintf("Trust - %s", values.DumpByte(t.body))))
	return content, nil
}
