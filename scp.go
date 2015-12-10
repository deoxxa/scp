// Package scp provides SCP functionality atop the go.crypto/ssh package.
package scp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kballard/go-shellquote"
	"golang.org/x/crypto/ssh"
)

// File is a file being read from or written to a remote host. It implements the
// io.Reader and os.FileInfo interfaces, with the io.Reader portion delegated
// through to a bufio.Reader in the case that this is a file being read from a
// remote host.
type File struct {
	io.Reader

	name string
	size int64
	mode os.FileMode
}

// NewFile constructs a new File object with the given parameters. The size must
// be provided in advance because the remote host has to know how large the file
// is, so it can reject it in advance if there's not enough space.
func NewFile(name string, size int64, mode os.FileMode, r io.Reader) *File {
	return &File{
		Reader: r,
		name:   name,
		size:   size,
		mode:   mode,
	}
}

// IsDir will always return false.
func (f File) IsDir() bool {
	return false
}

// Name returns the name of the file. It does not include the full path.
func (f File) Name() string {
	return f.name
}

// Size returns the size of the file in bytes.
func (f File) Size() int64 {
	return f.size
}

// Mode returns the mode reported by the remote side.
func (f File) Mode() os.FileMode {
	return f.mode
}

// ModTime returns the modification time of the file. It is currently not
// implemented and returns a zero value.
func (f File) ModTime() time.Time {
	return time.Time{}
}

// Sys always returns nil.
func (f File) Sys() interface{} {
	return nil
}

// Read opens a session on the provided ssh.Client to run the scp program
// remotely in "from" mode, and handles the SCP protocol to the degree required
// to read the content of a single file.
//
// Errors that occur before the content is being read will be returned directly
// from Read, while errors that occur during content reception will be returned
// via the Reader (e.g. from Reader.Read).
func Read(c *ssh.Client, file string) (*File, error) {
	s, err := c.NewSession()
	if err != nil {
		return nil, err
	}

	stdout, err := s.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stdin, err := s.StdinPipe()
	if err != nil {
		return nil, err
	}

	rw := bufio.NewReadWriter(bufio.NewReader(stdout), bufio.NewWriter(stdin))

	if err := s.Start(shellquote.Join("scp", "-qf", file)); err != nil {
		return nil, err
	}

	if err := rw.WriteByte(0); err != nil {
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		return nil, err
	}

	b, err := rw.ReadByte()
	if err != nil {
		return nil, err
	}

	switch b {
	case 0x01, 0x02:
		l, err := rw.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}

		m := map[byte]string{
			0x01: "warning",
			0x02: "error",
		}

		return nil, fmt.Errorf("%s: %q", m[b], string(bytes.TrimRight(l, "\n")))
	}

	if err := rw.UnreadByte(); err != nil {
		return nil, err
	}

	l, err := rw.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	mode, size, name, err := parseCopy(l)
	if err != nil {
		return nil, err
	}

	if err := rw.WriteByte(0); err != nil {
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		return nil, err
	}

	r, w := io.Pipe()

	go func() {
		defer s.Close()

		var err error

		defer func() {
			if err != nil {
				w.CloseWithError(err)
			} else {
				w.Close()
			}
		}()

		err = func() error {
			t := 0

			for {
				b := make([]byte, min(1024, int(size)-t))

				n, err := stdout.Read(b)
				if err == io.EOF {
					break
				} else if err != nil {
					return err
				}

				w.Write(b[0:n])
				t += n

				if int64(t) == size {
					break
				}
			}

			if err := rw.WriteByte(0); err != nil {
				return err
			}
			if err := rw.Flush(); err != nil {
				return err
			}

			if _, err = io.Copy(ioutil.Discard, rw); err == io.EOF {
				return nil
			} else if err != nil {
				return err
			}

			return nil
		}()
	}()

	return NewFile(name, size, mode, r), nil
}

// Write writes the given File to the directory specified. It returns a list of
// warnings and maybe an error on failure. Warnings are non-fatal, errors are
// fatal. If there are warnings returned, they're probably important.
func Write(c *ssh.Client, dir string, file *File) ([]string, error) {
	s, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	stdout, err := s.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stdin, err := s.StdinPipe()
	if err != nil {
		return nil, err
	}

	rw := bufio.NewReadWriter(bufio.NewReader(stdout), bufio.NewWriter(stdin))

	if err := s.Start(shellquote.Join("scp", "-t", dir)); err != nil {
		return nil, err
	}

	if _, err := rw.WriteString(fmt.Sprintf("C0%s %d %s\n", strconv.FormatUint(uint64(file.Mode()), 8), file.Size(), file.Name())); err != nil {
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		return nil, err
	}

	var warnings []string

	if b, err := rw.ReadByte(); err != nil {
		return nil, err
	} else if b == 1 || b == 2 {
		msg, err := rw.ReadString('\n')
		if err != nil {
			return nil, err
		}

		msg = strings.TrimSpace(msg)

		if b == 2 {
			return nil, fmt.Errorf(msg)
		}

		warnings = append(warnings, msg)
	}

	if _, err := io.Copy(rw, file); err != nil {
		return warnings, err
	}
	if err := rw.Flush(); err != nil {
		return warnings, err
	}

	if b, err := rw.ReadByte(); err != nil {
		return nil, err
	} else if b == 1 || b == 2 {
		msg, err := rw.ReadString('\n')
		if err != nil {
			return nil, err
		}

		msg = strings.TrimSpace(msg)

		if b == 2 {
			return nil, fmt.Errorf(msg)
		}

		warnings = append(warnings, msg)
	}

	return warnings, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}

	return b
}

func parseCopy(l []byte) (os.FileMode, int64, string, error) {
	if l[0] != 'C' {
		return 0, 0, "", fmt.Errorf("invalid first byte; expected C but got %02x", l[0])
	}

	bits := bytes.Split(bytes.TrimRight(l, "\n"), []byte(" "))

	rawMode, err := strconv.ParseUint(string(bits[0][1:]), 8, 32)
	if err != nil {
		return 0, 0, "", err
	}
	mode := os.FileMode(uint32(rawMode))

	size, err := strconv.ParseInt(string(bits[1]), 10, 32)
	if err != nil {
		return 0, 0, "", err
	}

	return mode, size, string(bits[2]), nil
}
