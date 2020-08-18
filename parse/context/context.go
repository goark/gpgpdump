package context

import (
	"fmt"
	"strings"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

//Context class fir parsing packets
type Context struct {
	options map[OptCode]bool
	SymAlgMode
	SigCreationTime *values.DateTime
	KeyCreationTime *values.DateTime
}

//OptFunc is self-referential function for functional options pattern
type OptFunc func(*Context)

// New returns a new Context instance
func New(opts ...OptFunc) *Context {
	c := &Context{options: map[OptCode]bool{}, SymAlgMode: ModeNotSpecified}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

//Set returns closure as type OptFunc
func Set(code OptCode, f bool) OptFunc {
	return func(c *Context) { c.Set(code, f) }
}

//SetByString returns closure as type OptFunc
func SetByString(name string, f bool) OptFunc {
	return func(c *Context) { c.Set(GetOptCode(name), f) }
}

//Set sets option to Context.
func (c *Context) Set(code OptCode, f bool) {
	if c == nil {
		return
	}
	if code.integer() > 0 {
		c.options[code] = f
	}
}

//Set sets option to Context.
func (c *Context) Get(code OptCode) bool {
	if c == nil {
		return false
	}
	if f, ok := c.options[code]; ok {
		return f
	}
	return false
}

//Armor return flag value of armorFlag
func (c *Context) Armor() bool { return c.Get(ARMOR) }

//Cert return flag value of certFlag
func (c *Context) Cert() bool { return c.Get(CERT) || c.Get(DEBUG) }

//Debug return flag value of debugFlag
func (c *Context) Debug() bool { return c.Get(DEBUG) }

//GDump return flag value of gdumpFlag
func (c *Context) GDump() bool { return c.Get(GDUMP) || c.Get(DEBUG) }

//Integer return flag value of intFlag
func (c *Context) Integer() bool { return c.Get(INTEGER) || c.Get(DEBUG) }

//Literal return flag value of literalFlag
func (c *Context) Literal() bool { return c.Get(LITERAL) || c.Get(DEBUG) }

//Marker return flag value of markerFlag
func (c *Context) Marker() bool { return c.Get(MARKER) || c.Get(DEBUG) }

//Private return flag value of privateFlag
func (c *Context) Private() bool { return c.Get(PRIVATE) || c.Get(DEBUG) }

//UTC return flag value of utcFlag
func (c *Context) UTC() bool { return c.Get(UTC) }

//Stringer
func (c *Context) String() string {
	strs := []string{}
	for cd := 1; cd <= len(optcodeMap); cd++ {
		flag := false
		switch OptCode(cd) {
		case ARMOR:
			flag = c.Armor()
		case CERT:
			flag = c.Cert()
		case DEBUG:
			flag = c.Debug()
		case GDUMP:
			flag = c.GDump()
		case INTEGER:
			flag = c.Integer()
		case LITERAL:
			flag = c.Literal()
		case MARKER:
			flag = c.Marker()
		case PRIVATE:
			flag = c.Private()
		case UTC:
			flag = c.UTC()
		}
		strs = append(strs, fmt.Sprintf("%v:%v", OptCode(cd), flag))
	}
	return strings.Join(strs, ",")
}

/* Copyright 2016-2020 Spiegel
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
