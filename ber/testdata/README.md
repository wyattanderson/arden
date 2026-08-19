# BER fixture corpus

These compact hexadecimal fixtures are independently transcribed from the BER
encoding rules in [X.690 §8](https://www.itu.int/rec/T-REC-X.690) and the LDAP
message envelope in [RFC 4511 §4.1.1](https://www.rfc-editor.org/rfc/rfc4511#section-4.1.1).
They are kept as text so their bytes can be reviewed directly. Each line in a
fixture is one complete BER element without whitespace.

The corpus deliberately contains only public structural values: no directory
data, credentials, DNs, or controls.
