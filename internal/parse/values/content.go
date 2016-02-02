package values

import (
	"bytes"
	"strings"
)

// Indent is indent size
type Indent int

// Fill space for Indent
func (ind Indent) Fill(str string) string {
	return ind.String() + str
}

func (ind Indent) String() string {
	if ind <= 0 {
		return ""
	}
	return strings.Repeat("\t", int(ind))
}

//Content is output strings
type Content []string

//NewContent returns Content.
func NewContent() Content {
	return make(Content, 0, 8)
}

func (c Content) String() string {
	if c == nil {
		return ""
	}
	buf := bytes.NewBuffer(make([]byte, 0, 128))
	for _, l := range c {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}
	return string(buf.Bytes())
}

//Add adding Content
func (c Content) Add(a Content) Content {
	if a != nil {
		return append(c, a...)
	}
	return c
}

//AddIndent adding Content with indent
func (c Content) AddIndent(a Content, i Indent) Content {
	if a != nil {
		for _, l := range a {
			c = append(c, i.Fill(l))
		}
	}
	return c
}
