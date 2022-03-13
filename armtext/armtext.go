package armtext

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/ecode"
)

const (
	armorBoundery          = "-----BEGIN PGP"
	armorBounderyExcept    = "-----BEGIN PGP SIGNED"
	armorBounderyTerminate = "-----END PGP"
)

func Get(r io.Reader) (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}
	armorFlag := false
	armorEndFlag := false
	scn := bufio.NewScanner(r)
	for scn.Scan() {
		str := scn.Text()
		if !armorFlag {
			if strings.HasPrefix(str, armorBoundery) && !strings.HasPrefix(str, armorBounderyExcept) {
				armorFlag = true
			}
		}
		if armorFlag && !armorEndFlag {
			fmt.Fprintln(buf, str)
			if strings.HasPrefix(str, armorBounderyTerminate) {
				armorEndFlag = true
			}
		}
	}
	if err := scn.Err(); err != nil {
		return nil, errs.Wrap(err)
	}
	if !armorFlag || !armorEndFlag {
		return nil, errs.Wrap(ecode.ErrArmorText)
	}
	return buf, nil
}

/* Copyright 2020 Spiegel
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
