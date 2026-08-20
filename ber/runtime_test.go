package ber_test

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/wyattanderson/arden/ber"
)

func limits() ber.Limits { return ber.DefaultLimits() }

func TestIdentifierBoundaries(t *testing.T) {
	tests := []struct {
		name string
		id   ber.Identifier
		want []byte
	}{
		{"short universal", ber.Identifier{Class: ber.ClassUniversal, Number: 30}, []byte{0x1e}},
		{"first high tag", ber.Identifier{Class: ber.ClassApplication, Number: 31}, []byte{0x5f, 0x1f}},
		{"high tag", ber.Identifier{Class: ber.ClassContextSpecific, Constructed: true, Number: 0x3fff}, []byte{0xbf, 0xff, 0x7f}},
		{"maximum tag", ber.Identifier{Class: ber.ClassPrivate, Number: math.MaxUint32}, []byte{0xdf, 0x8f, 0xff, 0xff, 0xff, 0x7f}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ber.AppendIdentifier(nil, test.id, math.MaxUint32)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, test.want) {
				t.Fatalf("AppendIdentifier() = %x, want %x", got, test.want)
			}
			e, err := ber.DecodeElement(append(got, 0), limits())
			if err != nil {
				t.Fatal(err)
			}
			if e.Identifier != test.id {
				t.Fatalf("identifier = %#v, want %#v", e.Identifier, test.id)
			}
		})
	}
}

func TestLengthBoundaries(t *testing.T) {
	for _, length := range []int{0, 127, 128, 255, 256, 65535, 65536} {
		t.Run("length", func(t *testing.T) {
			value := bytes.Repeat([]byte{0x42}, length)
			encoded, err := ber.AppendOctetString(nil, value)
			if err != nil {
				t.Fatal(err)
			}
			r, err := ber.NewReader(encoded, limits())
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.OctetString()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, value) || r.Remaining() != 0 {
				t.Fatalf("round trip failed for length %d", length)
			}
		})
	}
}

func TestPrimitiveRoundTrips(t *testing.T) {
	for _, value := range []int64{math.MinInt64, -129, -128, -1, 0, 1, 127, 128, math.MaxInt64} {
		encoded, err := ber.AppendInteger(nil, value)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ber.NewReader(encoded, limits())
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.Integer()
		if err != nil || got != value {
			t.Fatalf("Integer(%d) = %d, %v", value, got, err)
		}
	}
	encoded, err := ber.AppendBoolean(nil, true)
	if err != nil || !bytes.Equal(encoded, []byte{1, 1, 0xff}) {
		t.Fatalf("true BOOLEAN = %x, %v", encoded, err)
	}
}

func TestReaderRejectsLDAPRestrictionsAtomically(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		read func(*ber.Reader) error
		want error
	}{
		{"indefinite", []byte{0x04, 0x80}, func(r *ber.Reader) error { _, err := r.OctetString(); return err }, ber.ErrIndefiniteLength},
		{"constructed octet", []byte{0x24, 0x00}, func(r *ber.Reader) error { _, err := r.OctetString(); return err }, ber.ErrPrimitiveRequired},
		{"boolean true must be ff", []byte{0x01, 0x01, 0x01}, func(r *ber.Reader) error { _, err := r.Boolean(); return err }, ber.ErrInvalidBoolean},
		{"null contents", []byte{0x05, 0x01, 0x00}, func(r *ber.Reader) error { return r.Null() }, ber.ErrInvalidNull},
		{"nonminimal high tag", []byte{0x1f, 0x1e, 0x00}, func(r *ber.Reader) error { _, err := r.ReadElement(); return err }, ber.ErrInvalidIdentifier},
		{"nonminimal long length", []byte{0x04, 0x81, 0x7f}, func(r *ber.Reader) error { _, err := r.ReadElement(); return err }, ber.ErrInvalidLength},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, err := ber.NewReader(test.data, limits())
			if err != nil {
				t.Fatal(err)
			}
			err = test.read(r)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if r.Offset() != 0 {
				t.Fatalf("failed primitive advanced cursor to %d", r.Offset())
			}
		})
	}
}

func TestReaderLimits(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		data := []byte{0x30, 0x02, 0x30, 0x00}
		l := limits()
		l.MaxDepth = 1
		r, _ := ber.NewReader(data, l)
		child, err := r.Sequence()
		if err != nil {
			t.Fatal(err)
		}
		_, err = child.Sequence()
		var limit *ber.LimitError
		if !errors.As(err, &limit) || limit.Limit != "depth" {
			t.Fatalf("error = %v, want depth limit", err)
		}
	})
	t.Run("elements", func(t *testing.T) {
		l := limits()
		l.MaxElements = 1
		r, _ := ber.NewReader([]byte{0x05, 0x00, 0x05, 0x00}, l)
		if err := r.Null(); err != nil {
			t.Fatal(err)
		}
		if err := r.Null(); err == nil {
			t.Fatal("second element accepted")
		}
	})
}

func TestSkipElementValidatesNestedLimits(t *testing.T) {
	t.Run("peek does not advance", func(t *testing.T) {
		r, err := ber.NewReader([]byte{0x04, 0x00}, limits())
		if err != nil {
			t.Fatal(err)
		}
		id, err := r.PeekIdentifier()
		if err != nil {
			t.Fatal(err)
		}
		if id != ber.OctetStringIdentifier || r.Offset() != 0 {
			t.Fatalf("PeekIdentifier() = %s at offset %d", id, r.Offset())
		}
	})

	t.Run("unknown extension cannot bypass depth", func(t *testing.T) {
		data := []byte{0x30, 0x02, 0x30, 0x00}
		l := limits()
		l.MaxDepth = 1
		r, err := ber.NewReader(data, l)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.SkipElement(); err == nil {
			t.Fatal("SkipElement accepted nested value beyond depth limit")
		}
	})
}

func TestFramerEverySplit(t *testing.T) {
	frame := []byte{0x30, 0x81, 0x80}
	frame = append(frame, bytes.Repeat([]byte{0}, 128)...)
	for split := 0; split <= len(frame); split++ {
		t.Run("split", func(t *testing.T) {
			reader := &splitReader{parts: [][]byte{frame[:split], frame[split:]}}
			framer, err := ber.NewFramer(reader, limits())
			if err != nil {
				t.Fatal(err)
			}
			got, err := framer.Next()
			if err != nil {
				t.Fatalf("split %d: %v", split, err)
			}
			if !bytes.Equal(got, frame) {
				t.Fatalf("split %d: got %x", split, got)
			}
			got[0] = 0
			if frame[0] == 0 {
				t.Fatal("frame aliases source")
			}
		})
	}
}

func TestFramerTruncation(t *testing.T) {
	frame := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	for n := 0; n < len(frame); n++ {
		framer, err := ber.NewFramer(bytes.NewReader(frame[:n]), limits())
		if err != nil {
			t.Fatal(err)
		}
		_, err = framer.Next()
		if !errors.Is(err, ber.ErrTruncated) {
			t.Fatalf("truncation at %d: %v", n, err)
		}
	}
}

func TestReaderTruncation(t *testing.T) {
	frame := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	for n := 0; n < len(frame); n++ {
		t.Run("truncation", func(t *testing.T) {
			r, err := ber.NewReader(frame[:n], limits())
			if err != nil {
				t.Fatal(err)
			}
			_, err = r.ReadElement()
			if !errors.Is(err, ber.ErrTruncated) {
				t.Fatalf("truncation at %d: %v", n, err)
			}
			if r.Offset() != 0 {
				t.Fatalf("truncation at %d advanced cursor to %d", n, r.Offset())
			}
		})
	}
}

type splitReader struct {
	parts [][]byte
}

func (r *splitReader) Read(p []byte) (int, error) {
	for len(r.parts) > 0 && len(r.parts[0]) == 0 {
		r.parts = r.parts[1:]
	}
	if len(r.parts) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.parts[0][:1])
	r.parts[0] = r.parts[0][n:]
	return n, nil
}

func FuzzDecodeElement(f *testing.F) {
	for _, seed := range [][]byte{{0x05, 0x00}, {0x30, 0x03, 0x02, 0x01, 0x01}, {0x04, 0x80}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ber.DecodeElement(data, limits())
		r, err := ber.NewReader(data, limits())
		if err == nil {
			for !r.Empty() {
				if _, err := r.ReadElement(); err != nil {
					break
				}
			}
		}
	})
}

func FuzzPrimitiveDecoders(f *testing.F) {
	for _, seed := range [][]byte{{0x01, 0x01, 0xff}, {0x02, 0x01, 0x01}, {0x04, 0x00}, {0x05, 0x00}, {0x30, 0x00}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, read := range []func(*ber.Reader){
			func(r *ber.Reader) { _, _ = r.Boolean() },
			func(r *ber.Reader) { _, _ = r.Integer() },
			func(r *ber.Reader) { _, _ = r.Enumerated() },
			func(r *ber.Reader) { _, _ = r.OctetString() },
			func(r *ber.Reader) { _ = r.Null() },
			func(r *ber.Reader) { _, _ = r.Sequence() },
			func(r *ber.Reader) { _, _ = r.Set() },
		} {
			r, err := ber.NewReader(data, limits())
			if err == nil {
				read(r)
			}
		}
	})
}

func FuzzFramer(f *testing.F) {
	for _, seed := range [][]byte{{0x05, 0x00}, {0x30, 0x03, 0x02, 0x01, 0x01}, {0x04, 0x80}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		framer, err := ber.NewFramer(bytes.NewReader(data), limits())
		if err == nil {
			_, _ = framer.Next()
		}
	})
}

func BenchmarkFramer(b *testing.B) {
	frame := append([]byte{0x30, 0x82, 0x10, 0x00}, bytes.Repeat([]byte{0}, 4096)...)
	b.ReportAllocs()
	for range b.N {
		framer, err := ber.NewFramer(bytes.NewReader(frame), limits())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := framer.Next(); err != nil {
			b.Fatal(err)
		}
	}
}
