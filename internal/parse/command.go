package parse

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"

	"github.com/spiegel-im-spiegel/gocli"
	"github.com/spiegel-im-spiegel/gpgpdump/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
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
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		if c.Aflag {
			err = errs.ErrNotArmor
		} else {
			//retry parse by parseBinary()
			reader := bytes.NewReader(data)
			content, err = parseBinary(c.Options, reader)
		}
	}
	if err != nil {
		return err
	}
	var str string
	if c.Jflag {
		str, err = content.MarshalJSON()
	} else {
		str, err = content.MarshalTOML()
	}
	if err != nil {
		return err
	}
	c.Output(str)
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

/* Copyright 2016 Spiegel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
