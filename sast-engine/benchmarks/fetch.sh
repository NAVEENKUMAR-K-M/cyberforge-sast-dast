#!/bin/sh
# Downloads the vulnerable apps used for evaluation, at the commits the keys were labelled against.
# These are deliberately vulnerable. Only scan their source, or run them on your own machine.
#
# Safe to re-run: an app is skipped only if the exact commit is already checked out, and a
# half-finished download from a dropped connection is cleared and retried.
cd "$(dirname "$0")" || exit 1
export GIT_TERMINAL_PROMPT=0  # fail instead of asking for a GitHub password
mkdir -p external
failed=""

fetch() {
    name=$1 repo=$2 commit=$3 dir="external/$1"
    if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" = "$commit" ]; then
        echo "$name already there"
        return 0
    fi
    for attempt in 1 2 3; do
        rm -rf "$dir"
        if git init -q "$dir" \
            && git -C "$dir" remote add origin "https://github.com/$repo" \
            && git -C "$dir" fetch -q --depth 1 origin "$commit" \
            && git -C "$dir" checkout -q FETCH_HEAD; then
            echo "$name ready"
            return 0
        fi
        echo "$name: download failed (attempt $attempt of 3)" >&2
        sleep 2
    done
    rm -rf "$dir"
    return 1
}

fetch dvwa digininja/DVWA a1978a2fed195acd093010af6395f86a281537ca || failed="$failed dvwa"
fetch mutillidae webpwnized/mutillidae 126a1fdb4ff977f87e980d018f0def477afc3d5d || failed="$failed mutillidae"
fetch bwapp raesene/bWAPP 53bcfdd59c02dcfdbf79e218f0a99c54ff42d799 || failed="$failed bwapp"
fetch xvwa s4n7h0/xvwa fb30fa517d288e618b521d252f61107ef6a24797 || failed="$failed xvwa"

if [ -n "$failed" ]; then
    echo "could not download:$failed. Check your connection and run this again." >&2
    exit 1
fi
