package tag11

import (
	"fmt"

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
	filename := string(t.body[2 : 2+flen])
	ftime := uint32(values.Octets2Int(t.body[2+flen : 2+flen+4]))
	data := t.body[2+flen+4:]

	content = append(content, (indent + 1).Fill(t.format(f)))
	content = append(content, (indent + 1).Fill(t.filename(filename)))
	content = append(content, (indent + 1).Fill(t.ftime(ftime)))
	content = append(content, (indent + 1).Fill(t.data(data)))
	return content, nil
}

func (t Tag11) format(f values.LiteralFormat) string {
	return fmt.Sprintf("Format - %v", f)
}

func (t Tag11) filename(filename string) string {
	return fmt.Sprintf("File name - %s", filename)
}

func (t Tag11) ftime(ftime uint32) string {
	return fmt.Sprintf("Modification time of a file - %s", values.StringRFC3339UNIX(ftime, t.Uflag))
}

func (t Tag11) data(data []byte) string {
	dump := "..."
	if t.Lflag {
		dump = values.DumpByte(data)
	}
	return fmt.Sprintf("Literal data - %s", dump)
}
