#!/usr/bin/env bash
set -euo pipefail

no_cache=false
push_image=false

while [[ $# -gt 0 ]]; do
	case "$1" in
		--no-cache)
			no_cache=true
			;;
		--push)
			push_image=true
			;;
		-h|--help)
			echo "Usage: $0 [--push] [--no-cache]"
			echo "  Default: builds locally for current host architecture without pushing to Docker"
			echo "  --push: builds multi-architecture images and pushes to Docker registry"
			exit 0
			;;
		*)
			echo "Unknown argument: $1" >&2
			echo "Usage: $0 [--push] [--no-cache]" >&2
			exit 1
			;;
	esac

	shift
done

cd "$(dirname "$0")/.."

if [[ "$push_image" == true ]]; then
	docker_args=(docker buildx build --platform linux/amd64,linux/arm64 --push)
else
	docker_args=(docker buildx build --load)
fi

if [[ "$no_cache" == true ]]; then
	docker_args+=(--no-cache)
fi
docker_args+=(-t edipal/scim-server-impl-go:dev .)

"${docker_args[@]}"
