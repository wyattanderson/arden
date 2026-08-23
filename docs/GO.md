# Go style conventions

## Intentionally ignored close errors

When a deferred `Close` error cannot change the result of the operation, use a
direct defer and a focused linter suppression:

```go
//nolint:errcheck // The terminal response determines the operation result.
defer stream.Close()
```

Do not wrap the call in an anonymous function solely to assign its error to
`_`. If a close error is meaningful, handle or join it instead of suppressing
it.
