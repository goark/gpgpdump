package ecode

import "fmt"

//ECode is error codes for gpgpdump
type ECode int

const (
	ErrNullPointer ECode = iota + 1
	ErrInvalidOption
	ErrArmorText
	ErrInvalidWhence
	ErrInvalidOffset
	ErrUserID
	ErrHTTPStatus
	ErrEmptyKeyServer
)

var errMessage = map[ECode]string{
	ErrNullPointer:    "Null reference instance",
	ErrInvalidOption:  "Invalid option",
	ErrArmorText:      "Cannot find OpenPGP armor boundary",
	ErrInvalidWhence:  "Invalid whence",
	ErrInvalidOffset:  "Invalid offset",
	ErrUserID:         "No user id",
	ErrEmptyKeyServer: "Empty name of key serve",
	ErrHTTPStatus:     "Bad HTTP(S) status",
}

func (e ECode) Error() string {
	if s, ok := errMessage[e]; ok {
		return s
	}
	return fmt.Sprintf("Unknown error (%d)", int(e))
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
