package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// tag11 class for Literal Data Packet
type tag11 struct {
	tagInfo
}

//newTag11 return tag11 instance
func newTag11(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag11{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing Literal Data Packet
func (t *tag11) Parse() (*info.Item, error) {
	rootInfo := t.ToItem()
	f, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.LiteralFormat(f).ToItem())
	flen, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	fname, err := t.reader.ReadBytes(int64(flen))
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.LiteralFname(string(fname)).ToItem(t.cxt.Debug()))
	ftime, err2 := values.NewDateTime(t.reader, t.cxt.UTC())
	if err2 != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.FileTimeItem(ftime, t.cxt.Debug()))
	rootInfo.Add(values.RawData(t.reader, "Literal data", t.cxt.Literal()))
	return rootInfo, nil
}

/* Copyright 2016-2019 Spiegel
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
