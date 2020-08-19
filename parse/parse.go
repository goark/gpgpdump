package parse

import (
	"io"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/tags"
	"golang.org/x/crypto/openpgp/packet"
)

//Parse returns packet result.
func (r *Parser) Parse() (*result.Info, error) {
	if r == nil {
		return result.New(), nil
	}
	for {
		op, err := r.next()
		if err != nil {
			return r.info, errs.Wrap(err)
		}
		if op == nil {
			return r.info, nil
		}
		tag := tags.NewTag(op, r.cxt)
		item, err := tag.Parse()
		if err != nil {
			return r.info, errs.Wrap(err)
		}
		r.info.Add(item)
		switch t := tag.(type) {
		case *tags.Tag08: //Compressed Data Packet
			if t.Reader() != nil {
				parser := newParser(r.cxt, packet.NewOpaqueReader(t.Reader()), result.New())
				info, err := parser.Parse()
				if err != nil {
					return r.info, errs.Wrap(err)
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
}

func (r *Parser) next() (*packet.OpaquePacket, error) {
	op, err := r.opaqueReader.Next()
	if err != nil {
		if !errs.Is(err, io.EOF) { //EOF is not error
			return nil, errs.Wrap(err)
		}
		return nil, nil
	}
	return op, nil
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
