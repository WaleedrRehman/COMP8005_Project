#!/bin/bash

START=1
END=4
SPECIAL_THREAD=10

for ((threads=START; threads<=END; threads++)); do
    echo "Running with $threads threads..."
    ./brute_force "$threads"
    echo "----------------------------------"
done

if ((SPECIAL_THREAD < START || SPECIAL_THREAD > END)); then
    echo "Running with $SPECIAL_THREAD threads..."
    ./brute_force "$SPECIAL_THREAD"
    echo "----------------------------------"
fi
