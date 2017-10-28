package tags

import (
	"fmt"

	openpgp "golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//subParser class for pasing sub-packet
type subParser struct {
	cxt            *context.Context
	tagID          values.TagID
	opaqueSubpacke []*openpgp.OpaqueSubpacket
	item           *info.Item
}

//newSubparser returns subParser for parsing packet
func newSubparser(cxt *context.Context, tagID values.TagID, name string, body []byte) (*subParser, error) {
	item := info.NewItem(
		info.Name(name),
		info.Note(fmt.Sprintf("%d bytes", len(body))),
		info.DumpStr(values.DumpBytes(body, cxt.Debug()).String()),
	)
	osps, err := openpgp.OpaqueSubpackets(body)
	return &subParser{cxt: cxt, tagID: tagID, opaqueSubpacke: osps, item: item}, err
}

//Parse returns sub-packet info.
func (sp *subParser) Parse() (*info.Item, error) {
	for _, osp := range sp.opaqueSubpacke {
		item, err := NewSubs(sp.cxt, osp, sp.tagID).Parse()
		if err != nil {
			break
		}
		sp.item.Add(item)
	}
	return sp.item, nil
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