package errs

import "fmt"

//Num is error number for gpgpdumo
type Num int

const (
	ErrNullPointer Num = iota + 1
	ErrInvalidOption
	ErrArmorText
	ErrInvalidWhence
	ErrInvalidOffset
)

var errMessage = map[Num]string{
	ErrNullPointer:   "Null reference instance",
	ErrInvalidOption: "Invalid option",
	ErrArmorText:     "Cannot find OpenPGP armor boundary",
	ErrInvalidWhence: "Invalid whence",
	ErrInvalidOffset: "Invalid offset",
}

func (n Num) Error() string {
	if s, ok := errMessage[n]; ok {
		return s
	}
	return fmt.Sprintf("Unknown error (%d)", int(n))
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
