#!/bin/sh
set -eu

if [ -n "${KRB5_KEYTAB:-}" ]; then
	kinit -k -t "${KRB5_KEYTAB}" "${KRB5_PRINCIPAL:?KRB5_PRINCIPAL is required}"
else
	: "${KRB5_PASSWORD:?KRB5_PASSWORD or KRB5_KEYTAB is required}"
	printf '%s\n' "${KRB5_PASSWORD}" | kinit "${KRB5_PRINCIPAL:?KRB5_PRINCIPAL is required}"
fi

exec /usr/local/bin/arden-freeipa-whoami
