#!/bin/sh

writefile=$1
writestr=$2

if [ -z "$writefile" ]; then
  echo "no write file specified"
  exit 1
fi

if [ -z "$writestr" ]; then
  echo "no write string specified"
  exit 1
fi

mkdir -p "$(dirname "$writefile")"

if ! printf "%s" "$writestr" >"$writefile"; then
  echo "Error: Could not create file '$writefile'" >&2
  exit 1
fi
