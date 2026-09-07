package ldapmodel

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestAddEncodingOwnershipAndModelClasses(t *testing.T) {
	classes := []string{"person", "posixAccount"}
	model := NewModel("dc=example", arden.ScopeSubtree, classes, NewAttribute[attributeTestModel]("uid", StringCodec), arden.NewAttributeSelectors("uid"),
		func(arden.Entry) (attributeTestModel, error) { return attributeTestModel{}, nil })
	classes[0] = "changed"
	serverError := errors.New("server rejected Add")
	executor := &addRecordingExecutor{err: serverError}
	ctx := t.Context()
	dao := NewDAO(arden.NewClient(executor), model).WithContext(ctx)

	mail := NewAttribute[attributeTestModel]("mail", StringCodec)
	emails := []string{"alice@example.test", "other@example.test"}
	assignment := Set(mail, emails...)
	emails[0] = "changed"
	photo := NewAttribute[attributeTestModel]("jpegPhoto", BytesCodec)
	data := []byte{0, 0xff}
	photos := [][]byte{data}
	photoAssignment := Set(photo, photos...)
	photos[0] = []byte("different")
	data[0] = 1

	err := dao.Add("alice",
		Set(mail, "old@example.test"), assignment, photoAssignment,
		Set(NewAttribute[attributeTestModel]("uidNumber", Uint32Codec), 0),
		Set(NewAttribute[attributeTestModel]("gecos", StringCodec), ""),
		Set(NewAttribute[attributeTestModel]("CN;lang-en;lang-de", StringCodec), "old"),
		Set(NewAttribute[attributeTestModel]("cn;LANG-DE;LANG-EN", StringCodec), "new"),
	)
	require.ErrorIs(t, err, serverError)
	assert.Equal(t, 1, executor.calls)
	assert.Equal(t, ctx, executor.ctx)
	request := executor.operation.Untyped().Protocol.(*rfc4511.AddRequest)
	assert.Equal(t, arden.LDAPDN("uid=alice,dc=example"), request.Entry)
	entry := arden.Entry{Attributes: request.Attributes}
	assert.Equal(t, []string{"alice"}, entry.Values("uid"))
	assert.Equal(t, []string{"person", "posixAccount"}, entry.Values("objectClass"))
	assert.Equal(t, []string{"alice@example.test", "other@example.test"}, entry.Values("mail"))
	assert.Equal(t, []string{"0"}, entry.Values("uidNumber"))
	assert.Equal(t, []string{""}, entry.Values("gecos"))
	assert.Equal(t, []string{"new"}, entry.Values("cn;lang-de;lang-en"))
	assert.Equal(t, 7, entry.Attributes.Len())
	assert.Equal(t, []byte{1, 0xff}, entry.RawValue("jpegPhoto"))
	assert.Same(t, &data[0], &entry.RawValue("jpegPhoto")[0])
	stored, _ := entry.Attributes.Lookup("mail")
	assert.Same(t, &assignment.wire.Values[0], &stored.Values[0])

	// An add without assignments leaves other required attributes to the server.
	require.ErrorIs(t, dao.Add("empty"), serverError)
	request = executor.operation.Untyped().Protocol.(*rfc4511.AddRequest)
	assert.Equal(t, 2, request.Attributes.Len())
}

func TestAddRejectsInvalidAssignmentsBeforeSending(t *testing.T) {
	encodeError := errors.New("cannot encode")
	attribute := NewAttribute[attributeTestModel]("custom", Codec[string]{EncodeFunc: func(value string) ([]byte, error) {
		if value == "bad" {
			return nil, encodeError
		}
		return []byte(value), nil
	}})
	valid := Set(attribute, "good")
	executor := &addRecordingExecutor{}
	dao := NewDAO(arden.NewClient(executor), Model[attributeTestModel]{classes: []string{"person"}, rdn: NewAttribute[attributeTestModel]("uid", StringCodec)})
	for _, test := range []struct {
		name       string
		assignment Assignment[attributeTestModel]
		message    string
		cause      error
	}{
		{"zero assignment", Assignment[attributeTestModel]{}, "has no attribute", nil},
		{"empty name", Set(NewAttribute[attributeTestModel]("", StringCodec), "x"), "has no attribute", nil},
		{"empty values", Set(attribute), "has no values", nil},
		{"encoding", Set(attribute, "good", "bad"), "encode custom value 1", encodeError},
		{"missing codec", Set(NewAttribute[attributeTestModel, string]("missing", nil), "x"), "has no codec", nil},
		{"object class", Set(NewAttribute[attributeTestModel]("OBJECTclass", StringCodec), "other"), "objectClass is defined by the model", nil},
		{"object class option", Set(NewAttribute[attributeTestModel]("objectClass;lang-en", StringCodec), "other"), "objectClass is defined by the model", nil},
		{"object class OID", Set(NewAttribute[attributeTestModel]("2.5.4.0", StringCodec), "other"), "objectClass is defined by the model", nil},
		{"object class OID option", Set(NewAttribute[attributeTestModel]("2.5.4.0;lang-en", StringCodec), "other"), "objectClass is defined by the model", nil},
		{"naming attribute", Set(NewAttribute[attributeTestModel]("uid", StringCodec), "alice"), "naming attribute", nil},
		{"naming case", Set(NewAttribute[attributeTestModel]("UID", StringCodec), "bob"), "naming attribute", nil},
		{"naming option", Set(NewAttribute[attributeTestModel]("UID;lang-en", StringCodec), "bob"), "naming attribute", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Even an invalid assignment replaced later must prevent the request.
			err := dao.Add("alice", valid, test.assignment, valid)
			require.ErrorContains(t, err, test.message)
			if test.cause != nil {
				require.ErrorIs(t, err, test.cause)
			}
			assert.Zero(t, executor.calls)
		})
	}
	dao = NewDAO(arden.NewClient(executor), Model[attributeTestModel]{})
	require.ErrorContains(t, dao.Add("alice", valid), "no base object classes")
	assert.Zero(t, executor.calls)
}

func TestAddModelOwnedNaming(t *testing.T) {
	for _, test := range []struct {
		name string
		base arden.LDAPDN
		want arden.LDAPDN
	}{
		{"alice", "dc=example", "cn=alice,dc=example"},
		{"alice", "", "cn=alice"},
		{"", "dc=example", "cn=,dc=example"},
		{" Alice ", "dc=example", `cn=\ Alice\ ,dc=example`},
		{" ", "dc=example", `cn=\ ,dc=example`},
		{"#Alice", "dc=example", `cn=\#Alice,dc=example`},
		{"Alice # Example", "dc=example", "cn=Alice # Example,dc=example"},
		{`a"+,;<>\=b`, "dc=example", `cn=a\"\+\,\;\<\>\\\=b,dc=example`},
		{"a\x00\n\r\x7fb", "dc=example", `cn=a\00\0a\0d\7fb,dc=example`},
		{"Élodie 東京", "dc=example", "cn=Élodie 東京,dc=example"},
		{"uid=alice,dc=elsewhere", "dc=example", `cn=uid\=alice\,dc\=elsewhere,dc=example`},
	} {
		t.Run(test.name+"/"+string(test.base), func(t *testing.T) {
			serverError := errors.New("server response")
			executor := &addRecordingExecutor{err: serverError}
			model := NewModel(test.base, arden.ScopeSubtree, []string{"person"},
				NewAttribute[attributeTestModel]("cn", StringCodec), arden.NewAttributeSelectors("cn"),
				func(arden.Entry) (attributeTestModel, error) { return attributeTestModel{}, nil })
			dao := NewDAO(arden.NewClient(executor), model)
			require.ErrorIs(t, dao.Add(test.name), serverError)
			assert.Equal(t, 1, executor.calls)
			require.IsType(t, &rfc4511.AddRequest{}, executor.operation.Untyped().Protocol)
			request := executor.operation.Untyped().Protocol.(*rfc4511.AddRequest)
			assert.Equal(t, test.want, request.Entry)
			entry := arden.Entry{Attributes: request.Attributes}
			assert.Equal(t, []string{test.name}, entry.Values("cn"))
		})
	}
}

func TestAddNamingCodecAndValidation(t *testing.T) {
	encoded := []byte("Alice, Example")
	var encodes int
	naming := NewAttribute[attributeTestModel]("cn", Codec[string]{EncodeFunc: func(value string) ([]byte, error) {
		encodes++
		assert.Equal(t, "alice", value)
		return encoded, nil
	}})
	serverError := errors.New("server response")
	executor := &addRecordingExecutor{err: serverError}
	model := NewModel("dc=example", arden.ScopeSubtree, []string{"person"}, naming,
		arden.NewAttributeSelectors("cn"), func(arden.Entry) (attributeTestModel, error) { return attributeTestModel{}, nil })
	dao := NewDAO(arden.NewClient(executor), model)
	require.ErrorIs(t, dao.Add("alice"), serverError)
	assert.Equal(t, 1, encodes)
	request := executor.operation.Untyped().Protocol.(*rfc4511.AddRequest)
	assert.Equal(t, arden.LDAPDN(`cn=Alice\, Example,dc=example`), request.Entry)
	entry := arden.Entry{Attributes: request.Attributes}
	assert.Equal(t, encoded, entry.RawValue("cn"))
	assert.Same(t, &encoded[0], &entry.RawValue("cn")[0])

	encodeError := errors.New("cannot encode name")
	for _, test := range []struct {
		name    string
		naming  Attribute[attributeTestModel, string]
		message string
		cause   error
	}{
		{"missing", Attribute[attributeTestModel, string]{}, "invalid naming attribute", nil},
		{"option", NewAttribute[attributeTestModel]("cn;lang-en", StringCodec), "invalid naming attribute", nil},
		{"separator", NewAttribute[attributeTestModel]("cn=x,uid", StringCodec), "invalid naming attribute", nil},
		{"object class", NewAttribute[attributeTestModel]("OBJECTCLASS", StringCodec), "invalid naming attribute", nil},
		{"numeric OID", NewAttribute[attributeTestModel]("2.5.4.3", StringCodec), "invalid naming attribute", nil},
		{"missing codec", NewAttribute[attributeTestModel, string]("cn", nil), "has no codec", nil},
		{"encoding", NewAttribute[attributeTestModel]("cn", Codec[string]{EncodeFunc: func(string) ([]byte, error) {
			return nil, encodeError
		}}), "encode cn value 0", encodeError},
		{"invalid UTF-8", NewAttribute[attributeTestModel]("cn", Codec[string]{EncodeFunc: func(string) ([]byte, error) {
			return []byte{0xff}, nil
		}}), "invalid UTF-8", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := &addRecordingExecutor{}
			model.rdn = test.naming
			dao := NewDAO(arden.NewClient(executor), model)
			err := dao.Add("alice")
			require.ErrorContains(t, err, test.message)
			if test.cause != nil {
				require.ErrorIs(t, err, test.cause)
			}
			assert.Zero(t, executor.calls)
		})
	}
}

type addRecordingExecutor struct {
	calls     int
	ctx       context.Context
	operation arden.AnyOperation
	err       error
}

func (e *addRecordingExecutor) Do(ctx context.Context, operation arden.AnyOperation) (arden.ResponseStream, error) {
	e.calls++
	e.ctx = ctx
	e.operation = operation
	return nil, e.err
}
