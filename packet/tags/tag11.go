package tags

import (
	"github.com/spiegel-im-spiegel/errs"
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
		return rootInfo, errs.Wrapf(err, "illegal format in parsing tag %d", int(t.tag))
	}
	rootInfo.Add(values.LiteralFormat(f).ToItem())
	flen, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal length of file name in parsing tag %d", int(t.tag))
	}
	fname, err := values.NewLiteralFname(t.reader, int64(flen))
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal length of file name in parsing tag %d (length: %d bytes)", int(t.tag), int64(flen))
	}
	rootInfo.Add(fname.ToItem(t.cxt.Literal()))
	ftime, err := values.NewDateTime(t.reader, t.cxt.UTC())
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal timestump of file in parsing tag %d", int(t.tag))
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
