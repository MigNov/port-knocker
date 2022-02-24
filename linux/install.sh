#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: You have to run this script as root" >&2
    exit 1
fi

if [ ! -f ./send-packet-data ]; then
    echo "Error: Script send-packet-data is missing" >&2
    exit 1
fi

rm -f /bin/send-packet-data
cp send-packet-data /bin/send-packet-data
chmod 755 /bin/send-packet-data

echo "All installed"
exit 0
