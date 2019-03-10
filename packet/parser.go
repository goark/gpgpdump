package packet

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	openpgp "golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/gpgpdump/errs"
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
func NewParser(reader io.Reader, o options.Options) (*Parser, error) {
	if reader == nil {
		return nil, errs.Wrap(errs.ErrNullPointer, "no data for parsing packet")
	}
	var r io.Reader
	var err error
	if o.Armor() {
		r, err = newParserArmor(reader)
	} else {
		buf := new(bytes.Buffer)
		r, err = newParserArmor(io.TeeReader(reader, buf))
		if err != nil {
			r, err = buf, nil
		}
	}
	return newParser(context.New(o), openpgp.NewOpaqueReader(r), info.NewInfo()), err
}

func newParser(cxt *context.Context, op *openpgp.OpaqueReader, info *info.Info) *Parser {
	return &Parser{opaqueReader: op, cxt: cxt, info: info}
}

//ASCII Armor format only
func newParserArmor(r io.Reader) (io.Reader, error) {
	buf := getASCIIArmorText(r)
	if buf == nil {
		return nil, errs.Wrap(errs.ErrArmorText, "error in parsing armor text")
	}
	block, err := armor.Decode(buf)
	if err != nil {
		return nil, errs.Wrap(err, "error in parsing armor text")
	}
	return block.Body, nil
}

const (
	armorBoundery       = "-----BEGIN PGP"
	armorBounderyExcept = "-----BEGIN PGP SIGNED"
)

func getASCIIArmorText(r io.Reader) *bytes.Buffer {
	buf := new(bytes.Buffer)
	armorFlag := false
	scn := bufio.NewScanner(r)
	for scn.Scan() {
		str := scn.Text()
		if !armorFlag {
			if strings.HasPrefix(str, armorBoundery) && !strings.HasPrefix(str, armorBounderyExcept) {
				armorFlag = true
			}
		}
		if armorFlag {
			fmt.Fprintln(buf, str)
		}
	}
	if err := scn.Err(); err != nil {
		return nil
	}
	if !armorFlag {
		return nil
	}
	return buf
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
		tag := tags.NewTag(op, r.cxt)
		item, err := tag.Parse()
		if err != nil {
			return r.info, errs.Wrapf(err, "error in parsing packet")
		}
		r.info.Add(item)
		switch t := tag.(type) {
		case *tags.Tag08: //Compressed Data Packet
			if t.Reader() != nil {
				parser := newParser(r.cxt, openpgp.NewOpaqueReader(t.Reader()), info.NewInfo())
				info, err := parser.Parse()
				if err != nil {
					return r.info, errs.Wrapf(err, "error in parsing body of tag(8) packet")
				}
				if len(item.Items) > 0 {
					item = item.Items[len(item.Items)-1]
				}
				for _, itm := range info.Packets {
					item.Add(itm)
				}
			}
		default:
		}
	}
	return r.info, nil
}
func (r *Parser) next() (*openpgp.OpaquePacket, error) {
	op, err := r.opaqueReader.Next()
	if err != nil {
		if !errs.Is(err, io.EOF) { //EOF is not error
			return nil, errs.Wrap(err, "error in parsing OpaquePacket")
		}
		return nil, nil
	}
	return op, nil
}

/* Copyright 2017-2019 Spiegel
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
