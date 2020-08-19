package tags

import (
	"fmt"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

//subParser class for pasing sub-packet
type subParser struct {
	cxt            *context.Context
	tagID          values.TagID
	opaqueSubpacke []*packet.OpaqueSubpacket
	item           *result.Item
}

//newSubparser returns subParser for parsing packet
func newSubparser(cxt *context.Context, tagID values.TagID, name string, body []byte) (*subParser, error) {
	item := result.NewItem(
		result.Name(name),
		result.Note(fmt.Sprintf("%d bytes", len(body))),
		result.DumpStr(values.DumpBytes(body, cxt.Debug()).String()),
	)
	osps, err := packet.OpaqueSubpackets(body)
	return &subParser{cxt: cxt, tagID: tagID, opaqueSubpacke: osps, item: item}, errs.Wrap(err)
}

//Parse returns sub-packet result.
func (sp *subParser) Parse() (*result.Item, error) {
	var lastErr error
	for _, osp := range sp.opaqueSubpacke {
		item, err := NewSubs(sp.cxt, osp, sp.tagID).Parse()
		if err != nil {
			lastErr = err
			break
		}
		sp.item.Add(item)
	}
	return sp.item, lastErr
}

/* Copyright 2016-2020 Spiegel
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
