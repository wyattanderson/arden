package rfc4511

import (
	"fmt"

	"github.com/wyattanderson/arden/ber"
)

func contextPrimitive(number uint32) ber.Identifier {
	return ber.Identifier{Class: ber.ClassContextSpecific, Number: number}
}

func contextConstructed(number uint32) ber.Identifier {
	return ber.Identifier{Class: ber.ClassContextSpecific, Constructed: true, Number: number}
}

func applicationPrimitive(number uint32) ber.Identifier {
	return ber.Identifier{Class: ber.ClassApplication, Number: number}
}

func applicationConstructed(number uint32) ber.Identifier {
	return ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: number}
}

func implicitOctetsPacket[T ~string | ~[]byte](id ber.Identifier, value T) ber.Packet {
	return ber.Primitive(id, []byte(value))
}

func implicitBooleanPacket(id ber.Identifier, value bool) ber.Packet {
	b := byte(0)
	if value {
		b = 0xff
	}
	return ber.Primitive(id, []byte{b})
}

func resultResponsePacket(id ber.Identifier, result LDAPResult) ber.Packet {
	response := ber.Constructed(id)
	result.addPrefix(response)
	return response.Add(result.Extensions...).BERPacket()
}

func requireNonEmpty[T ~string | ~[]byte](name string, value T) error {
	if len(value) == 0 {
		return fmt.Errorf("arden: %s is empty", name)
	}
	return nil
}

func attributeValues[T ~[]byte](values []T) []AttributeValue {
	converted := make([]AttributeValue, len(values))
	for i := range values {
		converted[i] = AttributeValue(values[i])
	}
	return converted
}
