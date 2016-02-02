package private

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Private - Private Packet
type Private struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Private Packet
func New(opt *options.Options, tag values.Tag, body []byte) *Private {
	return &Private{Options: opt, tag: tag, body: body}
}

// Parse parsing Private Packet
func (t Private) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()

	dump := "..."
	if t.Pflag {
		dump = values.DumpByte(t.body)
	}
	content = append(content, indent.Fill(fmt.Sprintf("Private (%d bytes) - %s", len(t.body), dump)))
	return content, nil
}
