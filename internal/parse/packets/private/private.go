package private

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Private - Private Packet
type Private struct {
	*options.Options
	body []byte
}

//New return Tag11
func New(opt *options.Options, body []byte) *Private {
	return &Private{Options: opt, body: body}
}

// Parse parsing Literal Data Packet
func (t Private) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()

	dump := "..."
	if t.Pflag {
		dump = values.DumpByte(t.body)
	}
	content = append(content, indent.Fill(fmt.Sprintf("Private (%d bytes) - %s", len(t.body), dump)))
	return content, nil
}
