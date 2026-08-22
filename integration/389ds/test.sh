#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/../.." && pwd)"

default_image="quay.io/389ds/dirsrv@sha256:f2851654c5df545cd893d84bea8d08c28dc25f0930493fbfed1d8a6eacf657f7"
image="${ARDEN_389DS_IMAGE:-${default_image}}"
container_name="arden-389ds-$$-${RANDOM}"
tls_server_name="arden-389ds.test"
dm_password="Secret123"
container_started=false
integration_tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/arden-389ds.XXXXXX")"
ca_certificate="${integration_tmp_dir}/ca.crt"

cleanup() {
	status=$?
	trap - EXIT
	if [[ "${container_started}" == true ]]; then
		if (( status != 0 )); then
			docker logs --tail 200 "${container_name}" 2>&1 \
				| sed -E \
					-e 's/(temp root password set to).*/\1 [redacted]/I' \
					-e 's/(Root DN password:).*/\1 [redacted]/I' \
					-e 's/(IMPORTANT: Set cn=Directory Manager password to).*/\1 [redacted]/I' || true
		fi
		docker rm --force "${container_name}" >/dev/null 2>&1 || true
	fi
	if [[ -d "${integration_tmp_dir}" ]]; then
		rm -rf -- "${integration_tmp_dir}"
	fi
	exit "${status}"
}
trap cleanup EXIT

docker run \
	--detach \
	--rm \
	--name "${container_name}" \
	--hostname "${tls_server_name}" \
	--env "DS_DM_PASSWORD=${dm_password}" \
	--publish 127.0.0.1::3636 \
	"${image}" >/dev/null
container_started=true

ldaps_port="$(docker port "${container_name}" 3636/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | tail -n 1)"
if [[ -z "${ldaps_port}" ]]; then
	echo "could not determine the published 389ds LDAPS port" >&2
	exit 1
fi

ready=false
for _ in $(seq 1 90); do
	if ! docker inspect "${container_name}" --format '{{.State.Running}}' 2>/dev/null | grep -qx true; then
		echo "389ds container stopped before becoming ready" >&2
		exit 1
	fi
	if docker exec \
		--env LDAPTLS_CACERT=/data/config/ca.crt \
		"${container_name}" \
		ldapwhoami \
		-x \
		-H "ldaps://${tls_server_name}:3636" \
		-D "cn=Directory Manager" \
		-w "${dm_password}" >/dev/null 2>&1; then
		ready=true
		break
	fi
	sleep 1
done
if [[ "${ready}" != true ]]; then
	echo "389ds did not accept the configured LDAPS Directory Manager bind within 90 seconds" >&2
	exit 1
fi

docker cp "${container_name}:/data/config/ca.crt" "${ca_certificate}" >/dev/null
if [[ ! -s "${ca_certificate}" ]]; then
	echo "could not copy the 389ds test CA certificate" >&2
	exit 1
fi

(
	cd "${repo_dir}"
	ARDEN_389DS_ADDR="127.0.0.1:${ldaps_port}" \
	ARDEN_389DS_SERVER_NAME="${tls_server_name}" \
	ARDEN_389DS_CA_CERT="${ca_certificate}" \
	ARDEN_389DS_DM_PASSWORD="${dm_password}" \
	go test -tags=integration -run '^Test389DS' -count=1 .
)
