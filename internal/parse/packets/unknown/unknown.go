package unknown

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Unknown - Unknown Packet
type Unknown struct {
	*options.Options
	body []byte
}

//New return Tag11
func New(opt *options.Options, body []byte) *Unknown {
	return &Unknown{Options: opt, body: body}
}

// Parse parsing Literal Data Packet
func (t Unknown) Parse(indent values.Indent) (values.Content, error) {
	return nil, nil
}
