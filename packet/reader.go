package packet

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"golang.org/x/crypto/openpgp/armor"
)

//Reader class for pasing packet
type Reader struct {
	*options.Options
	reader io.Reader
}

//NewReader returns reader for parsing packet
func NewReader(data []byte, o *options.Options) (*Reader, error) {
	r, err := newReaderArmor(bytes.NewReader(data))
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		if o.Armor() {
			return nil, err
		}
		r, err = bytes.NewReader(data), nil
	}
	return &Reader{reader: r, Options: o}, err
}

//ASCII Armor format only
func newReaderArmor(r io.Reader) (io.Reader, error) {
	block, err := armor.Decode(r)
	if err != nil {
		return nil, err
	}
	fmt.Println(block.Type, block.Header)
	return block.Body, nil
}

//Parse returns packet info.
func (r *Reader) Parse() (*info.Info, error) {
	return info.NewInfo(), nil //stub
}

/* Copyright 2017 Spiegel
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
