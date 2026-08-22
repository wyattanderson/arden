#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/../.." && pwd)"

default_image="quay.io/389ds/dirsrv@sha256:f2851654c5df545cd893d84bea8d08c28dc25f0930493fbfed1d8a6eacf657f7"
image="${ARDEN_389DS_IMAGE:-${default_image}}"
container_name="arden-389ds-$$-${RANDOM}"
dm_password="Secret123"
container_started=false

cleanup() {
	status=$?
	trap - EXIT
	if [[ "${container_started}" == true ]]; then
		if (( status != 0 )); then
			docker logs --tail 200 "${container_name}" 2>&1 \
				| sed -E 's/(temp root password set to).*/\1 [redacted]/' || true
		fi
		docker rm --force "${container_name}" >/dev/null 2>&1 || true
	fi
	exit "${status}"
}
trap cleanup EXIT

docker run \
	--detach \
	--rm \
	--name "${container_name}" \
	--env "DS_DM_PASSWORD=${dm_password}" \
	--publish 127.0.0.1::3389 \
	"${image}" >/dev/null
container_started=true

ldap_port="$(docker port "${container_name}" 3389/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | tail -n 1)"
if [[ -z "${ldap_port}" ]]; then
	echo "could not determine the published 389ds LDAP port" >&2
	exit 1
fi

ready=false
for _ in $(seq 1 90); do
	if ! docker inspect "${container_name}" --format '{{.State.Running}}' 2>/dev/null | grep -qx true; then
		echo "389ds container stopped before becoming ready" >&2
		exit 1
	fi
	if docker exec "${container_name}" ldapwhoami \
		-x \
		-H ldap://localhost:3389 \
		-D "cn=Directory Manager" \
		-w "${dm_password}" >/dev/null 2>&1; then
		ready=true
		break
	fi
	sleep 1
done
if [[ "${ready}" != true ]]; then
	echo "389ds did not accept the configured Directory Manager bind within 90 seconds" >&2
	exit 1
fi

(
	cd "${repo_dir}"
	ARDEN_389DS_ADDR="127.0.0.1:${ldap_port}" \
	ARDEN_389DS_DM_PASSWORD="${dm_password}" \
	go test -tags=integration -run '^Test389DS' -count=1 .
)
