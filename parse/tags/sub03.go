package tags

import (
	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//sub03 class for Signature Expiration Time Sub-packet
type sub03 struct {
	subInfo
}

//newSub03 return sub03 instance
func newSub03(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub03{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Signature Expiration Timee Sub-packet
func (s *sub03) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	exp, err := values.NewExpire(s.reader, s.cxt.SigCreationTime)
	if err != nil {
		return rootInfo, errs.New("illegal Expiration Timee", errs.WithCause(err))
	}
	s.cxt.SigCreationTime = nil
	return exp.ToItem(rootInfo.Name, s.cxt.Debug()), nil
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
