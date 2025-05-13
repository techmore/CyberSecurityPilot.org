#!/bin/bash

export SESSION_AUTH_KEY="$(openssl rand -hex 32)"
cd /var/www/html
nohup ./main > output.log 2>&1 &
