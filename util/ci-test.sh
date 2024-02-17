#!/bin/bash -e

./c-socks5 -c '' &
SOCKS_PID=$!

sleep 1

curl -x socks5h://127.0.0.1:1080 --connect-timeout 8 -sv "https://google.com/generate_204"

echo "Done."
kill $SOCKS_PID
exit 0
