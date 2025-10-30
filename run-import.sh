#!/usr/bin/env bash
set -euo pipefail
docker run --rm --env-file /home/ubuntu/kev/.env \
  -v /home/ubuntu/kev/data:/app/data kev-import >> /var/log/kev-import.log 2>&1
