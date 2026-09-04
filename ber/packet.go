package ber

import "bytes"

type integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

type octets interface {
	~string | ~[]byte
}

// Packeter constructs one BER packet without serializing or validating it.
type Packeter interface {
	BERPacket() Packet
}

// Packet is one complete BER element. Packets are created with the primitive,
// constructed, or encoded constructors in this package.
type Packet struct {
	identifier Identifier
	value      []byte
	children   []Packet
	encoded    bool
	opaque     bool
}

// Primitive constructs a primitive packet with id and value.
func Primitive(id Identifier, value []byte) Packet {
	return primitive(id, bytes.Clone(value))
}

func primitive(id Identifier, value []byte) Packet {
	id.Constructed = false
	return Packet{identifier: id, value: value}
}

// WithContents constructs a packet with id and already-encoded contents. It is
// intended for preserved or deliberately malformed values that cannot be
// expressed as a packet tree.
func WithContents(id Identifier, value []byte) Packet {
	return Packet{identifier: id, value: bytes.Clone(value), opaque: true}
}

// Encoded constructs an opaque packet from an existing complete BER encoding.
func Encoded(value []byte) Packet {
	return Packet{value: bytes.Clone(value), encoded: true}
}

// OctetString constructs a universal OCTET STRING packet.
func OctetString[T octets](value T) Packet {
	return Primitive(OctetStringIdentifier, []byte(value))
}

// Integer constructs a universal INTEGER packet.
func Integer[T integer](value T) Packet {
	return integerPacket(IntegerIdentifier, value)
}

// IntegerWithIdentifier constructs an implicitly tagged INTEGER packet.
func IntegerWithIdentifier[T integer](id Identifier, value T) Packet {
	return integerPacket(id, value)
}

// Enumerated constructs a universal ENUMERATED packet.
func Enumerated[T integer](value T) Packet {
	return integerPacket(EnumeratedIdentifier, value)
}

func integerPacket[T integer](id Identifier, value T) Packet {
	return primitive(id, integerBytes(value))
}

// Boolean constructs an LDAP BOOLEAN packet.
func Boolean(value bool) Packet {
	b := byte(0)
	if value {
		b = 0xff
	}
	return primitive(BooleanIdentifier, []byte{b})
}

// Null constructs a universal NULL packet.
func Null() Packet {
	return primitive(NullIdentifier, nil)
}

// BERPacket returns p.
func (p Packet) BERPacket() Packet {
	return p
}

// Encode returns the packet's complete BER encoding in a new byte slice.
func (p Packet) Encode() []byte {
	return p.AppendTo(make([]byte, 0, p.encodedLength()))
}

// AppendTo appends the packet's complete BER encoding to dst. It may reuse
// dst's capacity but does not retain dst or modify its existing prefix.
func (p Packet) AppendTo(dst []byte) []byte {
	if p.encoded {
		return append(dst, p.value...)
	}
	contentLength := p.contentLength()
	dst = appendIdentifier(dst, p.identifier)
	dst = appendLength(dst, contentLength)
	if !p.identifier.Constructed || p.opaque {
		return append(dst, p.value...)
	}
	for i := range p.children {
		dst = p.children[i].AppendTo(dst)
	}
	return dst
}

func (p Packet) contentLength() int {
	if !p.identifier.Constructed || p.opaque {
		return len(p.value)
	}
	length := 0
	for i := range p.children {
		length += p.children[i].encodedLength()
	}
	return length
}

func (p Packet) encodedLength() int {
	if p.encoded {
		return len(p.value)
	}
	contentLength := p.contentLength()
	return identifierLength(p.identifier) + lengthLength(contentLength) + contentLength
}

// Envelope is a constructed BER packet under construction.
type Envelope struct {
	packet Packet
}

// Constructed creates an empty constructed envelope with id.
func Constructed(id Identifier) *Envelope {
	id.Constructed = true
	return &Envelope{packet: Packet{identifier: id}}
}

// Sequence creates an empty universal SEQUENCE envelope.
func Sequence() *Envelope {
	return Constructed(SequenceIdentifier)
}

// Set creates an empty universal SET envelope.
func Set() *Envelope {
	return Constructed(SetIdentifier)
}

// Add appends children to e in wire order.
func (e *Envelope) Add[T Packeter](children ...T) *Envelope {
	for _, child := range children {
		e.packet.children = append(e.packet.children, child.BERPacket())
	}
	return e
}

// BERPacket returns the constructed packet.
func (e *Envelope) BERPacket() Packet {
	return e.packet
}

func integerBytes[T integer](value T) []byte {
	if value < 0 {
		var raw [8]byte
		n := int64(value)
		for i := len(raw) - 1; i >= 0; i-- {
			raw[i] = byte(n)
			n >>= 8
		}
		start := 0
		for start < len(raw)-1 && raw[start] == 0xff && raw[start+1]&0x80 != 0 {
			start++
		}
		return bytes.Clone(raw[start:])
	}

	var raw [9]byte
	start := len(raw)
	n := uint64(value)
	for {
		start--
		raw[start] = byte(n)
		n >>= 8
		if n == 0 {
			break
		}
	}
	if raw[start]&0x80 != 0 {
		start--
		raw[start] = 0
	}
	return bytes.Clone(raw[start:])
}

func identifierLength(id Identifier) int {
	if id.Number < 31 {
		return 1
	}
	length := 1
	for number := id.Number; ; number >>= 7 {
		length++
		if number < 0x80 {
			break
		}
	}
	return length
}

func lengthLength(length int) int {
	if length < 128 {
		return 1
	}
	bytes := 0
	for ; length > 0; length >>= 8 {
		bytes++
	}
	return 1 + bytes
}
