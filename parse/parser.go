package parse

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/openpgp/armor"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/ecode"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/tags"
)

//Parser class for pasing packet
type Parser struct {
	pct  *tags.Packets
	info *result.Info
}

//New returns Parser instance
func New(cxt *context.Context, reader io.Reader) (*Parser, error) {
	if reader == nil {
		return nil, errs.Wrap(ecode.ErrNullPointer)
	}
	var r io.Reader
	var err error
	switch {
	case cxt.Armor():
		r, err = newReaderArmor(reader)
	default:
		buf := &bytes.Buffer{}
		r, err = newReaderArmor(io.TeeReader(reader, buf))
		if err != nil {
			r, err = buf, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return newParser(cxt, r, result.New())
}

//NewBytes returns Parser instance
func NewBytes(cxt *context.Context, data []byte) (*Parser, error) {
	return New(cxt, bytes.NewReader(data))
}

func newParser(cxt *context.Context, reader io.Reader, info *result.Info) (*Parser, error) {
	p, err := tags.NewPackets(cxt, reader)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &Parser{pct: p, info: info}, nil
}

func newReaderArmor(r io.Reader) (io.Reader, error) {
	buf := getASCIIArmorText(r)
	if buf == nil {
		return nil, errs.Wrap(ecode.ErrArmorText)
	}
	block, err := armor.Decode(buf)
	if err != nil {
		return nil, errs.Wrap(err)
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

/* Copyright 2017-2020 Spiegel
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
