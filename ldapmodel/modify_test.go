package ldapmodel

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
)

func TestChangeEncodingAndOwnership(t *testing.T) {
	mail := NewAttribute[attributeTestModel]("mail", StringCodec)
	values := []string{"alice@example.test", "other@example.test"}
	change := Replace(mail, values...)
	values[0] = "changed"
	require.NoError(t, change.err)
	assert.Equal(t, arden.Replace("mail", "alice@example.test", "other@example.test"), change.wire)

	photo := NewAttribute[attributeTestModel]("jpegPhoto", BytesCodec)
	data := []byte{0, 0xff}
	photos := [][]byte{data}
	change = Add(photo, photos...)
	photos[0] = []byte("different")
	data[0] = 1
	require.NoError(t, change.err)
	assert.Equal(t, arden.AddBytes("jpegPhoto", []byte{1, 0xff}), change.wire)
	assert.Same(t, &data[0], &change.wire.Modification.Values[0][0])
}

func TestModifyRejectsInvalidChangesBeforeSending(t *testing.T) {
	encodeError := errors.New("cannot encode")
	attribute := NewAttribute[attributeTestModel]("custom", Codec[string]{EncodeFunc: func(value string) ([]byte, error) {
		if value == "bad" {
			return nil, encodeError
		}
		return []byte(value), nil
	}})
	missing := NewAttribute[attributeTestModel, string]("missing", nil)
	valid := Replace(attribute, "good")
	executor := &modifyCountingExecutor{}
	dao := NewDAO(arden.NewClient(executor), Model[attributeTestModel]{})

	for _, test := range []struct {
		name    string
		changes []Change[attributeTestModel]
		message string
		cause   error
	}{
		{"empty", nil, "no changes", ErrEmptyChanges},
		{"zero change", []Change[attributeTestModel]{valid, {}}, "change 1 has no attribute", nil},
		{"empty name", []Change[attributeTestModel]{Replace(NewAttribute[attributeTestModel]("", StringCodec), "x")}, "has no attribute", nil},
		{"add encoding", []Change[attributeTestModel]{valid, Add(attribute, "good", "bad")}, "encode custom value 1", encodeError},
		{"delete encoding", []Change[attributeTestModel]{valid, Delete(attribute, "good", "bad")}, "encode custom value 1", encodeError},
		{"replace encoding", []Change[attributeTestModel]{valid, Replace(attribute, "good", "bad")}, "encode custom value 1", encodeError},
		{"missing codec", []Change[attributeTestModel]{valid, Replace(missing, "value")}, `attribute "missing" has no codec`, nil},
		{"missing codec on clear", []Change[attributeTestModel]{valid, Delete(missing)}, `attribute "missing" has no codec`, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := dao.Modify("uid=alice", test.changes...)
			require.ErrorContains(t, err, test.message)
			if test.cause != nil {
				require.ErrorIs(t, err, test.cause)
			}
			assert.Zero(t, executor.calls, "invalid changes must not send any request")
		})
	}
}

func TestModifyPassesContextAndServerError(t *testing.T) {
	ctx := t.Context()
	serverError := errors.New("server rejected modification")
	executor := &modifyCountingExecutor{err: serverError}
	dao := NewDAO(arden.NewClient(executor), Model[attributeTestModel]{}).WithContext(ctx)
	attribute := NewAttribute[attributeTestModel]("uid", StringCodec)
	err := dao.Modify("uid=alice", Replace(attribute, "bob"))
	require.ErrorIs(t, err, serverError)
	assert.Equal(t, 1, executor.calls)
	assert.Equal(t, ctx, executor.ctx)
}

type modifyCountingExecutor struct {
	calls int
	ctx   context.Context
	err   error
}

func (e *modifyCountingExecutor) Do(ctx context.Context, _ arden.AnyOperation) (arden.ResponseStream, error) {
	e.calls++
	e.ctx = ctx
	if e.err != nil {
		return nil, e.err
	}
	return nil, errors.New("unexpected Modify")
}
