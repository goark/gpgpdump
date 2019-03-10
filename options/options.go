package options

import (
	"fmt"
	"strings"
)

//Level is log level
type OptCode int

const (
	ARMOR   OptCode = iota //accepts ASCII input only
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
	return OptCode(-1)
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

//Options for gpgpdump
type Options map[OptCode]bool

//OptFunc is self-referential function for functional options pattern
type OptFunc func(Options)

// New returns a new Options instance
func New(opts ...OptFunc) Options {
	o := Options{}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

//Set returns closure as type OptFunc
func Set(code OptCode, f bool) OptFunc {
	return func(o Options) { o.Set(code, f) }
}

//SetByString returns closure as type OptFunc
func SetByString(name string, f bool) OptFunc {
	return func(o Options) { o.Set(GetOptCode(name), f) }
}

//Set sets option to Options.
func (o Options) Set(code OptCode, f bool) {
	if code.integer() >= 0 {
		o[code] = f
	}
}

//Set sets option to Options.
func (o Options) Get(code OptCode) bool {
	if f, ok := o[code]; ok {
		return f
	}
	return false
}

//Armor return flag value of armorFlag
func (o Options) Armor() bool { return o.Get(ARMOR) }

//Debug return flag value of debugFlag
func (o Options) Debug() bool { return o.Get(DEBUG) }

//GDump return flag value of gdumpFlag
func (o Options) GDump() bool { return o.Get(GDUMP) || o.Get(DEBUG) }

//Integer return flag value of intFlag
func (o Options) Integer() bool { return o.Get(INTEGER) || o.Get(DEBUG) }

//Literal return flag value of literalFlag
func (o Options) Literal() bool { return o.Get(LITERAL) || o.Get(DEBUG) }

//Marker return flag value of markerFlag
func (o Options) Marker() bool { return o.Get(MARKER) || o.Get(DEBUG) }

//Private return flag value of privateFlag
func (o Options) Private() bool { return o.Get(PRIVATE) || o.Get(DEBUG) }

//UTC return flag value of utcFlag
func (o Options) UTC() bool { return o.Get(UTC) }

//Stringer
func (o Options) String() string {
	strs := []string{}
	for c := 0; c < len(optcodeMap); c++ {
		flag := false
		switch OptCode(c) {
		case ARMOR:
			flag = o.Armor()
		case DEBUG:
			flag = o.Debug()
		case GDUMP:
			flag = o.GDump()
		case INTEGER:
			flag = o.Integer()
		case LITERAL:
			flag = o.Literal()
		case MARKER:
			flag = o.Marker()
		case PRIVATE:
			flag = o.Private()
		case UTC:
			flag = o.UTC()
		}
		strs = append(strs, fmt.Sprintf("%v:%v", OptCode(c), flag))
	}
	return strings.Join(strs, ",")
}

/* Copyright 2017-2019 Spiegel
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
