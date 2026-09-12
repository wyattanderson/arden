// Package clientmodel contains generated LDAP storage types and handwritten validation.
package clientmodel

import "errors"

// ErrInvalidMaxAge rejects stored maximum authentication ages that cannot be used.
var ErrInvalidMaxAge = errors.New("maximum authentication age must be positive")

// Validate adds an application constraint to the generated LDAP projection.
// It is called after decoding by the YAML model's validate hook.
func (c Client) Validate() error {
	if c.MaxAuthenticationAgeSeconds != nil && *c.MaxAuthenticationAgeSeconds == 0 {
		return ErrInvalidMaxAge
	}
	return nil
}

func validateClient(c Client) error { return c.Validate() }
