package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func decode(t *testing.T, encoded []byte, out ber.Unmarshaler) {
	t.Helper()
	r, err := ber.NewReader(encoded, ber.DefaultLimits())
	require.NoError(t, err)
	require.NoError(t, out.UnmarshalBER(r))
	require.NoError(t, r.RequireEmpty())
}

func requireDecodeError(t *testing.T, encoded []byte, out ber.Unmarshaler) {
	t.Helper()
	r, err := ber.NewReader(encoded, ber.DefaultLimits())
	require.NoError(t, err)
	require.Error(t, out.UnmarshalBER(r))
}

type rawControl struct{}

func (rawControl) BERPacket() ber.Packet { return ber.Sequence().BERPacket() }
