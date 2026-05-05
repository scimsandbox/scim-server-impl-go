#!/usr/bin/env bash
set -euo pipefail

no_cache=false

while [[ $# -gt 0 ]]; do
	case "$1" in
		--no-cache)
			no_cache=true
			;;
		-h|--help)
			echo "Usage: $0 [--no-cache]"
			exit 0
			;;
		*)
			echo "Unknown argument: $1" >&2
			echo "Usage: $0 [--no-cache]" >&2
			exit 1
			;;
	esac

	shift
done

cd "$(dirname "$0")/.."

docker_args=(docker buildx build --platform linux/amd64,linux/arm64 --push)
if [[ "$no_cache" == true ]]; then
	docker_args+=(--no-cache)
fi
docker_args+=(-t edipal/scim-server-impl-go:dev .)

"${docker_args[@]}"
