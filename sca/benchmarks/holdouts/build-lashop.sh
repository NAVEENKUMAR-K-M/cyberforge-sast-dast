#!/bin/sh
# Rebuilds the Laravel holdout: a fresh Laravel 11 skeleton with the shop's overlay, with its vendor/ tree.
# Usage: sca/benchmarks/holdouts/build-lashop.sh <empty output folder>   (needs Docker)
# Same install as sast-engine/benchmarks/lashop/Dockerfile, so it is the app that benchmark serves.
set -eu
OUT="${1:?usage: build-lashop.sh <output folder>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OVERLAY="$HERE/../../../sast-engine/benchmarks/lashop/overlay"
mkdir -p "$OUT"
docker run --rm -v "$OUT":/srv -w /srv -e COMPOSER_NO_SECURITY_BLOCKING=1 composer:2 \
    composer create-project laravel/laravel:^11.0 app --no-interaction --prefer-dist --no-scripts --no-progress
cp -R "$OVERLAY"/. "$OUT/app/"
echo "Built $OUT/app"
