package tags

import (
	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

// tag17 class for User Attribute Packet
type tag17 struct {
	tagInfo
}

//newTag17 return tag17 instance
func newTag17(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag17{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing User Attribute Packet
func (t *tag17) Parse() (*result.Item, error) {
	rootInfo := t.ToItem()
	subpcket, err := newSubparser(t.cxt, t.tag, "Subpacket", t.reader.GetBody())
	if err != nil {
		return rootInfo, errs.New("illegal subpacket", errs.WithCause(err))
	}
	itm, err := subpcket.Parse()
	if err != nil {
		return rootInfo, errs.Wrap(err)
	}
	rootInfo.Add(itm)
	return rootInfo, nil
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
