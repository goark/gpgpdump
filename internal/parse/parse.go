package parse

import (
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets"
	"github.com/spiegel-im-spiegel/gpgpdump/items"

	"golang.org/x/crypto/openpgp/armor"
)

func parseArmor(opt *options.Options, reader io.Reader) (*items.Packets, error) {
	block, err := armor.Decode(reader)
	if err != nil {
		return nil, err
	}
	return parse(opt, block.Body)
}

func parseBinary(opt *options.Options, reader io.Reader) (*items.Packets, error) {
	return parse(opt, reader)
}

func parse(opt *options.Options, body io.Reader) (*items.Packets, error) {
	pckts := packets.NewPackets(body)
	content := items.NewPackets()
	opt.ResetSymAlgMode()
	for {
		p, err := pckts.Next()
		if err != nil {
			return content, err
		}
		if p == nil {
			break
		}
		c, err := p.Parse(opt)
		if err != nil {
			return content, err
		}
		content.AddPacket(c)
	}
	return content, nil
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
