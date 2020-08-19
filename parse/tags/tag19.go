package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

// tag19 class for Modification Detection Code Packet
type tag19 struct {
	tagInfo
}

//newTag19 return tag19 instance
func newTag19(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag19{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing Modification Detection Code Packet
func (t *tag19) Parse() (*result.Item, error) {
	rootInfo := t.ToItem()
	itm := values.RawData(t.reader, "MDC", t.cxt.Debug())
	itm.Note = "SHA-1 (20 bytes)"
	rootInfo.Add(itm)
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
