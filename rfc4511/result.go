package rfc4511

import (
	"errors"

	"github.com/wyattanderson/arden/ber"
)

// ResultCode is the extensible LDAPResult resultCode ENUMERATED. Unknown
// numeric values are preserved rather than rejected.
//
// RFC 4511 section 4.1.9 and Appendix A.
type ResultCode int64

// LDAP result codes defined by RFC 4511.
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

// ResultResponse is implemented by terminal response values which carry an
// LDAPResult. It is the constraint used by typed single-response execution.
type ResultResponse interface {
	LDAPResult() LDAPResult
}

// BERPacket returns the LDAP result packet.
func (v LDAPResult) BERPacket() ber.Packet {
	result := ber.Sequence()
	v.addPrefix(result)
	return result.Add(v.Extensions...).BERPacket()
}

//revive:disable-next-line:exported
func (v *LDAPResult) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.SequenceIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the complete LDAPResult decoder to id.
func (v *LDAPResult) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		d := ber.NewDecoder(r).Constructed(id)
		decoded := d.Embed[LDAPResult]()
		decoded.Extensions = d.Extensions[UnknownField]()
		if err := d.End(); err != nil {
			return err
		}
		*v = decoded
		return nil
	})
}

// UnmarshalBERFields decodes the known LDAPResult components without an
// envelope or trailing extensions. The enclosing scope owns both. Referral
// identifiers are reserved so an enclosing response rejects duplicate or
// out-of-order referrals without knowing LDAPResult's internal schema.
func (v *LDAPResult) UnmarshalBERFields(d *ber.Decoder) error {
	d.Reserve(referralIdentifier)
	decoded := LDAPResult{
		ResultCode:        d.Enumerated[ResultCode](),
		MatchedDN:         d.Read[LDAPDN](),
		DiagnosticMessage: d.Read[LDAPString](),
	}
	if d.NextIs(referralIdentifier) {
		decoded.Referrals = d.Constructed(referralIdentifier).All[URI]()
		if len(decoded.Referrals) == 0 {
			d.Fail(errors.New("arden: referral requires at least one URI"))
		}
	}
	if err := d.Err(); err != nil {
		return err
	}
	if err := decoded.validateReferral(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

// addPrefix adds only the LDAPResult fields which can be embedded into
// BindResponse and ExtendedResponse before their operation-specific fields.
func (v LDAPResult) addPrefix(dst *ber.Envelope) {
	dst.Add(
		ber.Enumerated(v.ResultCode),
		ber.OctetString(v.MatchedDN),
		ber.OctetString(v.DiagnosticMessage),
	)
	if len(v.Referrals) > 0 {
		dst.Add(ber.Constructed(referralIdentifier).Add(v.Referrals...))
	}
}

func (v LDAPResult) validateReferral() error {
	if v.ResultCode == ResultReferral && len(v.Referrals) == 0 {
		return errors.New("arden: referral result requires at least one referral URI")
	}
	if v.ResultCode != ResultReferral && len(v.Referrals) != 0 {
		return errors.New("arden: referral URIs require the referral result code")
	}
	return nil
}
