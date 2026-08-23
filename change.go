package arden

import "github.com/wyattanderson/arden/rfc4511"

// Replace constructs a text-valued replace change.
func Replace(attribute string, values ...string) Change {
	return rfc4511.Replace(attribute, values...)
}

// AddValues constructs a text-valued add change.
func AddValues(attribute string, values ...string) Change {
	return rfc4511.AddValues(attribute, values...)
}

// DeleteValues constructs a text-valued delete change.
func DeleteValues(attribute string, values ...string) Change {
	return rfc4511.DeleteValues(attribute, values...)
}

// ReplaceBytes constructs a binary-valued replace change.
func ReplaceBytes(attribute string, values ...[]byte) Change {
	return rfc4511.ReplaceBytes(attribute, values...)
}

// AddBytes constructs a binary-valued add change.
func AddBytes(attribute string, values ...[]byte) Change {
	return rfc4511.AddBytes(attribute, values...)
}

// DeleteBytes constructs a binary-valued delete change.
func DeleteBytes(attribute string, values ...[]byte) Change {
	return rfc4511.DeleteBytes(attribute, values...)
}
