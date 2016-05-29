package values

import "io"

//GetBytes returns byte slice from stream
func GetBytes(reader io.Reader, size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	_, err := io.ReadFull(reader, buf)
	return buf, err
}

// Octets2Int returns integer from two-octets data
func Octets2Int(octets []byte) uint64 {
	rtn := uint64(0)
	if len(octets) <= 8 {
		for _, o := range octets {
			rtn = (rtn << 8) | uint64(o)
		}
	}
	return rtn
}

// Octets2IntLE returns integer from two-octets data (by little endian)
func Octets2IntLE(octets []byte) uint16 {
	rtn := uint16(0)
	if len(octets) == 2 {
		rtn = (uint16(octets[1]) << 8) | uint16(octets[0])
	}
	return rtn
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
