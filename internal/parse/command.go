package parse

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/spiegel-im-spiegel/gocli"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
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
	var buffer bytes.Buffer
	if err := toml.NewEncoder(&buffer).Encode(content); err != nil {
		return err
	}
	c.Output(buffer.String())
	if err != nil {
		return err
	}
	return nil
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
