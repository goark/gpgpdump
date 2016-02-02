package tag11

import (
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// Tag11 - Literal Data Packet
type Tag11 struct {
	*options.Options
	body []byte
}

//New return Tag11
func New(opt *options.Options, body []byte) *Tag11 {
	return &Tag11{Options: opt, body: body}
}

// Parse parsing Literal Data Packet
func (t Tag11) Parse(indent values.Indent) (values.Content, error) {
	content := values.NewContent()

	f := values.LiteralFormat(t.body[0])
	flen := int(t.body[1])
	filename := values.LiteralFname(t.body[2 : 2+flen])
	ftime := values.FileTime(values.Octets2Int(t.body[2+flen:2+flen+4]), t.Uflag)
	data := values.LiteralData(t.body[2+flen+4:], t.Lflag)

	content = append(content, (indent + 1).Fill(f.String()))
	content = append(content, (indent + 1).Fill(filename.String()))
	content = append(content, (indent + 1).Fill(ftime.String()))
	content = append(content, (indent + 1).Fill(data.String()))
	return content, nil
}
