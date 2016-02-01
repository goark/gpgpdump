package tag18

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag18 - Sym. Encrypted Integrity Protected Data Packet
type Tag18 struct {
	*options.Options
	body []byte
}

//New return Tag18
func New(opt *options.Options, body []byte) *Tag18 {
	return &Tag18{Options: opt, body: body}
}

// Parse parsing Sym. Encrypted Integrity Protected Data Packet
func (t Tag18) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()

	switch true {
	case t.Mode.IsSymEnc():
		content = append(content, (indent + 1).Fill("Encrypted data [sym alg is specified in sym-key encrypted session key] (plain text + MDC SHA1(20 bytes))"))
	case t.Mode.IsPubEnc():
		content = append(content, (indent + 1).Fill("Encrypted data [sym alg is specified in pub-key encrypted session key] (plain text + MDC SHA1(20 bytes))"))
	default:
		content = append(content, (indent + 1).Fill("Encrypted data"))
	}
	t.ResetSymAlgMode()
	return content, nil
}
