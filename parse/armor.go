package parse

import (
	"io"

	"golang.org/x/crypto/openpgp/armor"
)

// Parse armor file
func (c *Context) parseArmor(reader io.Reader) error {
	block, err := armor.Decode(reader)
	if err != nil {
		return err
	}
	return c.parse(block.Body)
}
