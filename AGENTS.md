# Testing

Always use rich, type-appropriate `testify/assert` and `testify/require`
assertions in Go tests. Never use `t.Fatalf` or hand-written failure branches
where an assertion expresses the check. Prefer helpers such as `NoError`,
`ErrorIs`, `ErrorContains`, `Len`, `Equal`, `Contains`, and `NotContains` over
boolean assertions. Use `require` for prerequisites needed to continue safely
(for example, successful decoding or a slice length before indexing), and
`assert` for independent checks. Apply the same rule to test helpers.
