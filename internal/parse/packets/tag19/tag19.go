package tag19

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag19 - Modification Detection Code Packet
type Tag19 struct {
	*options.Options
	body []byte
}

//New return Tag19
func New(opt *options.Options, body []byte) *Tag19 {
	return &Tag19{Options: opt, body: body}
}

// Parse parsing Modification Detection Code Packet
func (t Tag19) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()
	content = append(content, (indent + 1).Fill("MDC - SHA-1 (20 bytes)"))
	return content, nil
}
