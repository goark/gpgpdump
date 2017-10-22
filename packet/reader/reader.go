package reader

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

//Reader class as reading stream for []byte buffer
type Reader struct {
	buffer []byte
	offset int64
}

//NewReader returns Reader instance
func NewReader(data []byte) *Reader {
	return &Reader{buffer: data, offset: 0}
}

//Read returns []byte data (io.Reader compatible)
func (r *Reader) Read(p []byte) (int, error) {
	pl := len(p)
	b, err := r.ReadBytes(int64(pl))
	if err != nil {
		return 0, err
	}
	copy(p, b)
	return pl, nil
}

//ReadAt returns []byte data from off pinter (io.ReaderAt compatible)
func (r *Reader) ReadAt(p []byte, off int64) (int64, error) {
	if _, err := r.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	pl, err := r.Read(p)
	return int64(pl), err
}

//ReadByte returns byte data (io.ByteReader compatible)
func (r *Reader) ReadByte() (byte, error) {
	b, err := r.ReadBytes(1)
	if len(b) == 0 {
		return byte(0), err
	}
	return b[0], err
}

//WriteTo is copying buffer to io.Writer (io.WriterTo compatible)
func (r *Reader) WriteTo(w io.Writer) (int64, error) {
	size, err := bytes.NewReader(r.buffer).WriteTo(w)
	if err == nil {
		r.offset = r.Size()
	}
	return size, err
}

var (
	//ErrWhence as invalid whence in Reader.Seek function
	ErrWhence = errors.New("Reader.Seek: invalid whence")
	//ErrOffset as invalid offset in Reader.Seek function
	ErrOffset = errors.New("Reader.Seek: invalid offset")
)

//Seek is changing offset in buffer (io.Seeker compatible)
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	rl := r.Size()
	var origin int64
	switch whence {
	case io.SeekStart:
		origin = 0
	case io.SeekCurrent:
		origin = r.offset
	case io.SeekEnd:
		origin = rl
	default: //error ?
		return r.offset, ErrWhence
	}
	origin += offset
	if origin < 0 || origin > rl {
		return r.offset, ErrOffset
	}
	r.offset = origin
	return origin, nil
}

//Len returns buffer size (type int)
func (r *Reader) Len() int {
	return len(r.buffer)
}

//Size returns buffer size (type int64)
func (r *Reader) Size() int64 {
	return int64(r.Len())
}

//Rest returns rest size from offset
func (r *Reader) Rest() int64 {
	return r.Size() - r.offset
}

//ReadBytes returns []byte data from buffer offset
func (r *Reader) ReadBytes(size int64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	rl := r.Size()
	if r.offset >= rl {
		return nil, io.EOF
	}
	if r.offset+size > rl {
		return nil, io.ErrUnexpectedEOF
	}
	b := r.buffer[r.offset : r.offset+size]
	r.offset += size
	return b, nil
}

//Read2EOF returns bytes from offset to eof
func (r *Reader) Read2EOF() ([]byte, error) {
	rl := r.Size()
	if r.offset >= rl {
		return nil, io.EOF
	}
	b := r.buffer[r.offset:]
	r.offset += rl
	return b, nil
}

//DumpString returns string of byte dump (not move offset)
func (r *Reader) DumpString(off int64) string {
	if off >= r.Size() {
		return ""
	}
	data := r.buffer[off:]
	sep := ""
	var buf = make([]byte, 0, 16)
	for _, b := range data {
		//buf = append(buf, fmt.Sprintf("%s%#02x,", sep, b)...)
		buf = append(buf, fmt.Sprintf("%s%02x", sep, b)...)
		sep = " "
	}
	return string(buf)
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
