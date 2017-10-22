package packet

import (
	"bytes"
	"io"

	openpgp "golang.org/x/crypto/openpgp/packet"

	"github.com/pkg/errors"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/tags"
	"golang.org/x/crypto/openpgp/armor"
)

//Parser class for pasing packet
type Parser struct {
	cxt          *context.Context
	info         *info.Info
	opaqueReader *openpgp.OpaqueReader
}

//NewParser returns Parser for parsing packet
func NewParser(data []byte, o *options.Options) (*Parser, error) {
	if o == nil {
		o = options.NewOptions()
	}
	r, err := newParserArmor(bytes.NewReader(data))
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		if o.Armor() {
			return nil, err
		}
		r, err = bytes.NewReader(data), nil
	}
	return &Parser{opaqueReader: openpgp.NewOpaqueReader(r), cxt: context.NewContext(o), info: info.NewInfo()}, err
}

//ASCII Armor format only
func newParserArmor(r io.Reader) (io.Reader, error) {
	block, err := armor.Decode(r)
	if err != nil {
		return nil, err
	}
	return block.Body, nil
}

//Parse returns packet info.
func (r *Parser) Parse() (*info.Info, error) {
	if r == nil {
		return info.NewInfo(), nil
	}
	for {
		op, err := r.next()
		if err != nil {
			return r.info, err
		}
		if op == nil {
			break
		}
		item, err := tags.NewTag(op, r.cxt).Parse()
		if err != nil {
			return r.info, err
		}
		r.info.Add(item)
	}
	return r.info, nil //stub
}
func (r *Parser) next() (*openpgp.OpaquePacket, error) {
	op, err := r.opaqueReader.Next()
	if err != nil {
		if err != io.EOF { //EOF is not error
			return nil, errors.Wrap(err, "error in packet.Parser.next() function")
		}
		return nil, nil
	}
	return op, nil
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
