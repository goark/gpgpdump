package values

import "github.com/spiegel-im-spiegel/gpgpdump/parse/result"

const (
	//Unknown string
	Unknown = "Unknown"
)

const (
	//PrivateAlgName string
	PrivateAlgName = "Private/Experimental algorithm"
)

//Flag2Item returns Item instance for flag result.
func Flag2Item(flag byte, value string) *result.Item {
	if flag != 0x00 {
		return result.NewItem(
			result.Name("Flag"),
			result.Value(value),
		)
	}
	return nil
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
