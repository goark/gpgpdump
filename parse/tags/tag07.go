package tags

import (
	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// tag07 class for Secret-Subkey Packet
type tag07 struct {
	tagInfo
}

//newTag07 return tag07 instance
func newTag07(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag07{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing Secret-Subkey Packet
func (t *tag07) Parse() (*result.Item, error) {
	item, err := newTag05(t.cxt, t.tag, t.reader.GetBody()).Parse() //redirect to Tag05
	return item, errs.Wrap(err)
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
