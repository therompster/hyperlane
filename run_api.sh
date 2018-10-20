#!/bin/sh
if [ -z "$STY" ]; then exec screen -dm -S api /bin/bash "$0"; fi
python3.5 /opt/rest.py
