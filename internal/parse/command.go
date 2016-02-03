package parse

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/spiegel-im-spiegel/gocli"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Errors
var (
	ErrNotArmor = errors.New("binary input is not allowed")
)

// Context for gpgpdump
type Context struct {
	*gocli.UI
	*options.Options
	InputFile string
}

// Command returns a new Context instance
func Command(ui *gocli.UI) *Context {
	return &Context{UI: ui, Options: &options.Options{}}
}

// Run Application
func (c *Context) Run() error {
	data, err := c.readData() //buffering
	if err != nil {
		return err
	}

	reader := bytes.NewReader(data)
	content, err := parseArmor(c.Options, reader)
	if err == io.EOF {
		if c.Aflag {
			err = ErrNotArmor
		} else {
			//retry parse by parseBinary()
			reader := bytes.NewReader(data)
			content, err = parseBinary(c.Options, reader)
		}
	}
	var str string
	if c.Jflag {
		str, err = encodeJSON(content)
	} else {
		str, err = encodeTOML(content)
	}
	if err != nil {
		return err
	}
	c.Output(str)
	return nil
}

func encodeTOML(content *items.Packets) (string, error) {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(content); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func encodeJSON(content *items.Packets) (string, error) {
	buf, err := json.MarshalIndent(content, "", "  ")
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func (c *Context) readData() ([]byte, error) {
	if c.InputFile != "" {
		file, err := os.Open(c.InputFile) //maybe file path
		if err != nil {
			return nil, err
		}
		defer file.Close()
		c.Reader = file
	}
	return ioutil.ReadAll(c.Reader) //buffering
}
