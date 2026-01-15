#!/bin/bash
/ckb run &
CKB_RUN_PID=$!

/ckb miner &
CKB_MINER_PID=$!

echo "ckb run PID: $CKB_RUN_PID"
echo "ckb miner PID: $CKB_MINER_PID"

cleanup() {
    echo "Stopping ckb miner and ckb run..."
    kill -INT $CKB_MINER_PID 2>/dev/null
    kill -INT $CKB_RUN_PID 2>/dev/null
    wait $CKB_MINER_PID 2>/dev/null
    wait $CKB_RUN_PID 2>/dev/null
    echo "Done"
    exit 0
}

trap cleanup SIGINT SIGTERM

wait
