package packet

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"golang.org/x/crypto/openpgp/armor"
)

//Reader class for pasing packet
type Reader struct {
	*options.Options
	reader io.Reader
}

//NewReader returns reader for parsing packet
func NewReader(data []byte, o *options.Options) (*Reader, error) {
	r, err := newReaderArmor(bytes.NewReader(data))
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		if o.Armor() {
			return nil, err
		}
		r, err = bytes.NewReader(data), nil
	}
	return &Reader{reader: r, Options: o}, err
}

//ASCII Armor format only
func newReaderArmor(r io.Reader) (io.Reader, error) {
	block, err := armor.Decode(r)
	if err != nil {
		return nil, err
	}
	fmt.Println(block.Type, block.Header)
	return block.Body, nil
}

//Parse returns packet info.
func (r *Reader) Parse() (*info.Info, error) {
	return info.NewInfo(), nil //stub
}
