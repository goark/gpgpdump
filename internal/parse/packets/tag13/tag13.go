package tag13

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag13 - User ID Packet
type Tag13 struct {
	*options.Options
	body []byte
}

//New return Tag13
func New(opt *options.Options, body []byte) *Tag13 {
	return &Tag13{Options: opt, body: body}
}

// Parse parsing Literal Data Packet
func (t Tag13) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()
	content = append(content, (indent + 1).Fill(fmt.Sprintf("User ID - %s", string(t.body))))
	return content, nil
}
