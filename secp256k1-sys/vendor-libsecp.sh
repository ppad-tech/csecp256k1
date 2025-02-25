#!/usr/bin/env bash
set -e

# NB adapted from rust-secp256k1/secp256k1-sys/vendor-libsecp.sh
#
# https://github.com/rust-bitcoin/rust-secp256k1

# Set default variables
if [ -z "$SECP_VENDOR_GIT_ROOT" ]; then
    SECP_VENDOR_GIT_ROOT="$(git rev-parse --show-toplevel)"
else
    SECP_VENDOR_GIT_ROOT="$(realpath "$SECP_VENDOR_GIT_ROOT")"
fi
SECP_SYS="$SECP_VENDOR_GIT_ROOT"/secp256k1-sys
DEFAULT_VERSION_CODE=$(grep "^version" ../ppad-csecp256k1.cabal | sed 's/\./_/g' | sed 's/version: *\([0-9]\+.*\)/\1/')
DEFAULT_DEPEND_DIR="$SECP_SYS/depend"
DEFAULT_SECP_REPO=https://github.com/bitcoin-core/secp256k1.git

: "${SECP_VENDOR_VERSION_CODE:=$DEFAULT_VERSION_CODE}"
: "${SECP_VENDOR_DEPEND_DIR:=$DEFAULT_DEPEND_DIR}"
: "${SECP_VENDOR_SECP_REPO:=$DEFAULT_SECP_REPO}"
# CP_NOT_CLONE lets us just copy a directory rather than git cloning.
# This is usually a bad idea, since it will bring in build artifacts or any other
# junk from the source directory, but may be useful during development or CI.
: "${SECP_VENDOR_CP_NOT_CLONE:=no}"

echo "Using version code $SECP_VENDOR_VERSION_CODE. Set SECP_VENDOR_VERSION_CODE to override."
echo "Using depend directory $SECP_VENDOR_DEPEND_DIR. Set SECP_VENDOR_DEPEND_DIR to override."
echo "Using secp repository $SECP_VENDOR_SECP_REPO. Set SECP_VENDOR_SECP_REPO to override."

# Parse command-line options
SECP_REV=""
FORCE=no
while (( "$#" )); do
    case "$1" in
    -f)
        FORCE=yes
        ;;
    *)
        if [ -z "$SECP_REV" ]; then
            echo "Using secp256k1 revision $SECP_REV."
            SECP_REV="$1"
        else
            echo "WARNING: ignoring unknown command-line argument $1"
        fi
        ;;
    esac
    shift
done

if [ -z "$SECP_REV" ]; then
    echo "WARNING: No secp256k1 revision specified. Will use whatever we find at the git repo."
fi
echo

# Check if we will do anything destructive.

if [ "$FORCE" == "no" ]; then
    if ! git diff --quiet -- "*.hs"; then
        echo "ERROR: There appear to be modified source files. Check these in or pass -f (some source files will be modified to have symbols renamed)."
        exit 2
    fi
    if ! git diff --quiet -- "$SECP_VENDOR_DEPEND_DIR"; then
        echo "ERROR: The depend directory appears to be modified. Check it in or pass -f (this directory will be deleted)."
        exit 2
    fi
fi

DIR=./secp256k1

pushd "$SECP_VENDOR_DEPEND_DIR" > /dev/null
rm -rf "$DIR" || true

# Clone the repo. As a special case, if the repo is a local path and we have
# not specified a revision, just copy the directory rather than using 'git clone'.
# This lets us use non-git repos or dirty source trees as secp sources.
if [ "$SECP_VENDOR_CP_NOT_CLONE" == "yes" ]; then
    cp -r "$SECP_VENDOR_SECP_REPO" "$DIR"
    chmod -R +w "$DIR" # cp preserves write perms, which if missing will cause patch to fail
else
    git clone "$SECP_VENDOR_SECP_REPO" "$DIR"
fi

# Check out specified revision
pushd "$DIR" > /dev/null
if [ -n "$SECP_REV" ]; then
    git checkout "$SECP_REV"
fi
SOURCE_REV=$(git rev-parse HEAD || echo "[unknown revision from $SECP_VENDOR_SECP_REPO]")
rm -rf .git/ || true
popd

# Record revision
echo "# This file was automatically created by $(basename "$0")" > ./secp256k1-HEAD-revision.txt
echo "$SOURCE_REV" >> ./secp256k1-HEAD-revision.txt

# Prefix all methods with haskellsecp and a version prefix
find "$DIR" \
    -not -path '*/\.*' \
    -not -name "CHANGELOG.md" \
    -type f \
    -print0 | xargs -0 sed -i "/^#include/! s/secp256k1_/haskellsecp256k1_v${SECP_VENDOR_VERSION_CODE}_/g"
# special rule for a method that is not prefixed in libsecp
find "$DIR" \
    -not -path '*/\.*' \
    -type f \
    -print0 | xargs -0 sed -i "/^#include/! s/ecdsa_signature_parse_der_lax/haskellsecp256k1_v${SECP_VENDOR_VERSION_CODE}_ecdsa_signature_parse_der_lax/g"

cd "$SECP_SYS"

# Update the extern references in the Haskell FFI source files.
find "./lib/" \
    -name "*.hs" \
    -type f \
    -print0 | xargs -0 sed -i -r "s/haskellsecp256k1_v[0-9]+_[0-9]+_[0-9]+_(.*)([\"\(])/haskellsecp256k1_v${SECP_VENDOR_VERSION_CODE}_\1\2/g"

popd > /dev/null

