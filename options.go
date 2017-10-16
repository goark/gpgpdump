package gpgpdump

import "fmt"

const (
	//ArmorOpt is name of armor option
	ArmorOpt = "armor"
	//DebugOpt is name of debug option
	DebugOpt = "debug"
	//GDumpOpt is name of gdump option
	GDumpOpt = "gdump"
	//IntegerOpt is name of int option
	IntegerOpt = "int"
	//JSONOpt is name of json option
	JSONOpt = "json"
	//LiteralOpt is name of literal option
	LiteralOpt = "literal"
	//MarkerOpt is name of marker option
	MarkerOpt = "marker"
	//PrivateOpt is name of private option
	PrivateOpt = "private"
	//UTCOpt is name of utc option
	UTCOpt = "utc"
)

// Options for gpgpdump
type Options struct {
	armorFlag   bool //accepts ASCII input only
	debugFlag   bool //for debug
	gdumpFlag   bool //selects alternate (GnuPG type) dump format (not used)
	intFlag     bool //dumps multi-precision integers
	jsonFlag    bool //output with JSON format
	literalFlag bool //dumps literal packets (tag 11)
	markerFlag  bool //dumps marker packets (tag 10)
	privateFlag bool //dumps private packets (tag 60-63)
	utcFlag     bool //output UTC time
}

//OptFunc is self-referential function for functional options pattern
type OptFunc func(*Options)

// NewOptions returns a new UI instance
func NewOptions(opts ...OptFunc) *Options {
	o := &Options{}
	o.Option(opts...)
	return o
}

//Set returns closure as type OptFunc
func Set(name string, f bool) OptFunc {
	return func(o *Options) {
		o.Set(name, f)
	}
}

//Set sets option to Options.
func (o *Options) Set(name string, f bool) {
	switch name {
	case ArmorOpt:
		o.armorFlag = f
	case DebugOpt:
		o.debugFlag = f
	case GDumpOpt:
		o.gdumpFlag = f
	case IntegerOpt:
		o.intFlag = f
	case JSONOpt:
		o.jsonFlag = f
	case LiteralOpt:
		o.literalFlag = f
	case MarkerOpt:
		o.markerFlag = f
	case PrivateOpt:
		o.privateFlag = f
	case UTCOpt:
		o.utcFlag = f
	}
}

//Option sets options to Options.
func (o *Options) Option(opts ...OptFunc) {
	for _, opt := range opts {
		opt(o)
	}
}

//Armor return flag value of armorFlag
func (o *Options) Armor() bool { return o.armorFlag }

//Debug return flag value of debugFlag
func (o *Options) Debug() bool { return o.debugFlag }

//GDump return flag value of gdumpFlag
func (o *Options) GDump() bool { return o.gdumpFlag }

//Integer return flag value of intFlag
func (o *Options) Integer() bool { return o.intFlag }

//JSON return flag value of jsonFlag
func (o *Options) JSON() bool { return o.jsonFlag }

//Literal return flag value of literalFlag
func (o *Options) Literal() bool { return o.literalFlag }

//Marker return flag value of markerFlag
func (o *Options) Marker() bool { return o.markerFlag }

//Private return flag value of privateFlag
func (o *Options) Private() bool { return o.privateFlag }

//UTC return flag value of utcFlag
func (o *Options) UTC() bool { return o.utcFlag }

//Stringer
func (o *Options) String() string {
	return fmt.Sprint(
		ArmorOpt, ":", o.Armor(), ",",
		DebugOpt, ":", o.Debug(), ",",
		GDumpOpt, ":", o.GDump(), ",",
		IntegerOpt, ":", o.Integer(), ",",
		JSONOpt, ":", o.JSON(), ",",
		LiteralOpt, ":", o.Literal(), ",",
		MarkerOpt, ":", o.Marker(), ",",
		PrivateOpt, ":", o.Private(), ",",
		UTCOpt, ":", o.UTC())
}

/* Copyright 2017 Spiegel
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
