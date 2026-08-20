package rfc4511

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/wyattanderson/arden/ber"
)

// ResultCode is the extensible LDAPResult resultCode ENUMERATED. Unknown
// numeric values are preserved rather than rejected.
//
// RFC 4511 section 4.1.9 and Appendix A.
type ResultCode int64

const (
	ResultSuccess                      ResultCode = 0
	ResultOperationsError              ResultCode = 1
	ResultProtocolError                ResultCode = 2
	ResultTimeLimitExceeded            ResultCode = 3
	ResultSizeLimitExceeded            ResultCode = 4
	ResultCompareFalse                 ResultCode = 5
	ResultCompareTrue                  ResultCode = 6
	ResultAuthMethodNotSupported       ResultCode = 7
	ResultStrongerAuthRequired         ResultCode = 8
	ResultReferral                     ResultCode = 10
	ResultAdminLimitExceeded           ResultCode = 11
	ResultUnavailableCriticalExtension ResultCode = 12
	ResultConfidentialityRequired      ResultCode = 13
	ResultSASLBindInProgress           ResultCode = 14
	ResultNoSuchAttribute              ResultCode = 16
	ResultUndefinedAttributeType       ResultCode = 17
	ResultInappropriateMatching        ResultCode = 18
	ResultConstraintViolation          ResultCode = 19
	ResultAttributeOrValueExists       ResultCode = 20
	ResultInvalidAttributeSyntax       ResultCode = 21
	ResultNoSuchObject                 ResultCode = 32
	ResultAliasProblem                 ResultCode = 33
	ResultInvalidDNSyntax              ResultCode = 34
	ResultAliasDereferencingProblem    ResultCode = 36
	ResultInappropriateAuthentication  ResultCode = 48
	ResultInvalidCredentials           ResultCode = 49
	ResultInsufficientAccessRights     ResultCode = 50
	ResultBusy                         ResultCode = 51
	ResultUnavailable                  ResultCode = 52
	ResultUnwillingToPerform           ResultCode = 53
	ResultLoopDetect                   ResultCode = 54
	ResultNamingViolation              ResultCode = 64
	ResultObjectClassViolation         ResultCode = 65
	ResultNotAllowedOnNonLeaf          ResultCode = 66
	ResultNotAllowedOnRDN              ResultCode = 67
	ResultEntryAlreadyExists           ResultCode = 68
	ResultObjectClassModsProhibited    ResultCode = 69
	ResultAffectsMultipleDSAs          ResultCode = 71
	ResultOther                        ResultCode = 80
)

var referralIdentifier = ber.Identifier{
	Class:       ber.ClassContextSpecific,
	Constructed: true,
	Number:      3,
}

// LDAPResult is the common final result returned by LDAP operations. Referral
// must contain at least one URI exactly when ResultCode is ResultReferral.
// Extensions preserves allowed unknown trailing fields in source order.
//
// RFC 4511 sections 4.1.9 and 4.1.10.
type LDAPResult struct {
	ResultCode        ResultCode
	MatchedDN         LDAPDN
	DiagnosticMessage LDAPString
	Referrals         []URI
	Extensions        []UnknownField
}

func (v LDAPResult) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	contents, err := v.appendContents(nil)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendSequence(dst, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

func (v *LDAPResult) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return errors.New("rfc4511: nil LDAPResult receiver")
	}
	contents, err := r.Sequence()
	if err != nil {
		return err
	}
	decoded, err := decodeLDAPResultContents(contents)
	if err != nil {
		return err
	}
	*v = decoded
	return nil
}

func (v LDAPResult) appendContents(dst []byte) ([]byte, error) {
	start := len(dst)
	var err error
	if dst, err = v.appendPrefix(dst); err != nil {
		return dst[:start], err
	}
	if dst, err = appendUnknownFields(dst, v.Extensions); err != nil {
		return dst[:start], err
	}
	return dst, nil
}

// appendPrefix encodes only the LDAPResult fields which can be embedded into
// BindResponse and ExtendedResponse before their operation-specific fields.
func (v LDAPResult) appendPrefix(dst []byte) ([]byte, error) {
	start := len(dst)
	if err := v.validateReferral(); err != nil {
		return dst, err
	}
	var err error
	if dst, err = ber.AppendEnumerated(dst, int64(v.ResultCode)); err != nil {
		return dst[:start], err
	}
	if dst, err = ber.AppendOctetString(dst, v.MatchedDN); err != nil {
		return dst[:start], err
	}
	if dst, err = ber.AppendOctetString(dst, v.DiagnosticMessage); err != nil {
		return dst[:start], err
	}
	if len(v.Referrals) > 0 {
		referrals := make([]byte, 0)
		for i, uri := range v.Referrals {
			referrals, err = ber.AppendOctetString(referrals, uri)
			if err != nil {
				return dst[:start], fmt.Errorf("rfc4511: referral URI %d: %w", i, err)
			}
		}
		if dst, err = ber.AppendConstructed(dst, referralIdentifier, referrals); err != nil {
			return dst[:start], err
		}
	}
	return dst, nil
}

func (v LDAPResult) validateReferral() error {
	if v.ResultCode == ResultReferral && len(v.Referrals) == 0 {
		return errors.New("rfc4511: referral result requires at least one referral URI")
	}
	if v.ResultCode != ResultReferral && len(v.Referrals) != 0 {
		return errors.New("rfc4511: referral URIs require the referral result code")
	}
	return nil
}

func decodeLDAPResultContents(r *ber.Reader) (LDAPResult, error) {
	decoded, err := decodeLDAPResultPrefix(r)
	if err != nil {
		return LDAPResult{}, err
	}
	if err := decodeLDAPResultExtensions(r, &decoded); err != nil {
		return LDAPResult{}, err
	}
	return decoded, nil
}

// decodeLDAPResultPrefix consumes the LDAPResult fields shared by response
// types that append their own fields after COMPONENTS OF LDAPResult. It leaves
// trailing fields unread for the enclosing response to interpret.
func decodeLDAPResultPrefix(r *ber.Reader) (LDAPResult, error) {
	code, err := r.Enumerated()
	if err != nil {
		return LDAPResult{}, err
	}
	matchedDN, err := r.OctetString()
	if err != nil {
		return LDAPResult{}, err
	}
	diagnostic, err := r.OctetString()
	if err != nil {
		return LDAPResult{}, err
	}
	decoded := LDAPResult{
		ResultCode:        ResultCode(code),
		MatchedDN:         LDAPDN(bytes.Clone(matchedDN)),
		DiagnosticMessage: LDAPString(bytes.Clone(diagnostic)),
	}

	if !r.Empty() {
		id, err := r.PeekIdentifier()
		if err != nil {
			return LDAPResult{}, err
		}
		if id == referralIdentifier {
			referrals, err := r.Constructed(referralIdentifier)
			if err != nil {
				return LDAPResult{}, err
			}
			for !referrals.Empty() {
				uri, err := referrals.OctetString()
				if err != nil {
					return LDAPResult{}, err
				}
				decoded.Referrals = append(decoded.Referrals, URI(bytes.Clone(uri)))
			}
		}
	}
	if err := decoded.validateReferral(); err != nil {
		return LDAPResult{}, err
	}
	return decoded, nil
}

func decodeLDAPResultExtensions(r *ber.Reader, decoded *LDAPResult) error {
	if !r.Empty() {
		id, err := r.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == referralIdentifier {
			return errors.New("rfc4511: duplicate referral field")
		}
		fields, err := decodeUnknownFields(r)
		if err != nil {
			return err
		}
		decoded.Extensions = fields
	}
	if err := decoded.validateReferral(); err != nil {
		return err
	}
	return nil
}
