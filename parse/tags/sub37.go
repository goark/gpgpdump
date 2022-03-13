package tags

import (
	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//sub37 class for Attested Certifications Sub-packet
type sub37 struct {
	subInfo
}

//newSub37 return sub37 instance
func newSub37(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub37{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Attested Certifications Sub-packet
func (s *sub37) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	rootInfo.Add(values.RawData(s.reader, "certification digests", s.cxt.Cert()))
	return rootInfo, nil
}

/* Copyright 2019 Spiegel
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
