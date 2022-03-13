package tags

import (
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/ecode"
	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/result"
)

//Packets class is context data for OpenPGP packets
type Packets struct {
	cxt          *context.Context
	opaqueReader *packet.OpaqueReader
	tag          Tags
}

func NewPackets(cxt *context.Context, reader io.Reader) (*Packets, error) {
	if reader == nil {
		return nil, errs.Wrap(ecode.ErrNullPointer)
	}
	return &Packets{cxt: cxt, opaqueReader: packet.NewOpaqueReader(reader), tag: nil}, nil
}

func (p *Packets) Next() error {
	if p == nil {
		return errs.Wrap(ecode.ErrNullPointer)
	}
	op, err := p.opaqueReader.Next()
	if err != nil {
		return errs.Wrap(err)
	}
	p.tag = NewTag(op, p.cxt)
	return nil
}

func (p *Packets) Parse() (*result.Item, error) {
	if p == nil {
		return nil, errs.Wrap(ecode.ErrNullPointer)
	}
	if p.tag == nil {
		if err := p.Next(); err != nil {
			if !errs.Is(err, io.EOF) { //EOF is not error
				return nil, errs.Wrap(err)
			}
			return nil, nil
		}
	}
	item, err := p.tag.Parse()
	if err != nil {
		return nil, errs.Wrap(err)
	}
	switch t := p.tag.(type) {
	case *Tag08: //Compressed Data Packet
		if r := t.Reader(); r != nil {
			sp, err := NewPackets(p.cxt, r)
			if err != nil {
				return item, errs.Wrap(err)
			}
			for {
				if err := sp.Next(); err != nil {
					if !errs.Is(err, io.EOF) { //EOF is not error
						return item, errs.Wrap(err)
					}
					break
				}
				itm, err := sp.tag.Parse()
				if err != nil {
					return item, errs.Wrap(err)
				}
				item.Add(itm)
			}
		}
	default:
	}
	return item, nil
}

/* Copyright 2020 Spiegel
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
