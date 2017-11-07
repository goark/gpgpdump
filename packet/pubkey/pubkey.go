package pubkey

import (
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//Pubkey - information of public key algorithm packet
type Pubkey struct {
	cxt    *context.Context
	pubID  values.PubID
	size   int64
	reader *reader.Reader
}

//New returns new Pubkey instance
func New(cxt *context.Context, pubID values.PubID, r *reader.Reader) *Pubkey {
	return &Pubkey{cxt: cxt, pubID: pubID, size: r.Rest(), reader: r}
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
