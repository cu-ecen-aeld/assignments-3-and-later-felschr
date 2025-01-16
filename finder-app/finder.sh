#!/bin/sh

filesdir=$1
searchstr=$2

if [ ! -d "$filesdir" ]; then
  echo "no files directory provided"
  exit 1
fi

if [ -z "$searchstr" ]; then
  echo "no search string provided"
  exit 1
fi

X=$(ls "$filesdir" | wc -l)
Y=$(grep -r "$searchstr" "$filesdir" | wc -l)

echo "The number of files are $X and the number of matching lines are $Y"
