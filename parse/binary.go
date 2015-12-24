package parse

import "io"

// Parse binary file
func (c *Context) parseBinary(reader io.Reader) error {
	return c.parse(reader)
}
