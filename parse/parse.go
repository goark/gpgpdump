package parse

import (
	"io"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/result"
)

//Parse returns packet result.
func (p *Parser) Parse() (*result.Info, error) {
	if p == nil {
		return result.New(), nil
	}
	for {
		if err := p.pct.Next(); err != nil {
			if !errs.Is(err, io.EOF) { //EOF is not error
				return p.info, errs.Wrap(err)
			}
			return p.info, nil
		}
		item, err := p.pct.Parse()
		if err != nil {
			return p.info, errs.Wrap(err)
		}
		p.info.Add(item)
	}
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
