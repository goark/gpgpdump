package tag10

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag10 - Marker Packet (Obsolete Literal Packet)
type Tag10 struct {
	*options.Options
	tag  values.Tag
	body []byte
}

//New return Marker Packet (Obsolete Literal Packet)
func New(opt *options.Options, tag values.Tag, body []byte) *Tag10 {
	return &Tag10{Options: opt, tag: tag, body: body}
}

// Parse parsing Marker Packet (Obsolete Literal Packet)
func (t Tag10) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()

	dump := "..."
	if t.Mflag {
		//dump = values.DumpByte(t.body)
		dump = string(t.body)
	}
	content = append(content, (indent + 1).Fill(fmt.Sprintf("Literal (%d bytes) - %s", len(t.body), dump)))
	return content, nil
}
