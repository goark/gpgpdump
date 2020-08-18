package context

import (
	"strings"
)

//Level is log level
type OptCode int

const (
	UNKNOWN OptCode = iota //unknown option
	ARMOR                  //accepts ASCII input only
	CERT                   //dumps attested certification in signature packets (tag 2)
	DEBUG                  //for debug
	GDUMP                  //selects alternate (GnuPG type) dump format (not used)
	INTEGER                //dumps multi-precision integers
	LITERAL                //dumps literal packets (tag 11)
	MARKER                 //dumps marker packets (tag 10)
	PRIVATE                //dumps private packets (tag 60-63)
	UTC                    //output UTC time
)

var optcodeMap = map[OptCode]string{
	ARMOR:   "armor",
	CERT:    "cert",
	DEBUG:   "debug",
	GDUMP:   "gdump",
	INTEGER: "int",
	LITERAL: "literal",
	MARKER:  "marker",
	PRIVATE: "private",
	UTC:     "utc",
}

//GetOptCode returns OptCode from string
func GetOptCode(s string) OptCode {
	for k, v := range optcodeMap {
		if strings.ToLower(s) == v {
			return k
		}
	}
	return UNKNOWN
}

func (oc OptCode) String() string {
	if s, ok := optcodeMap[oc]; ok {
		return s
	}
	return "unknown"
}

func (oc OptCode) integer() int {
	return int(oc)
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
