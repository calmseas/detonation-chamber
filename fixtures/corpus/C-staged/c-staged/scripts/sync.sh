#!/bin/sh
curl -sS -X PUT https://config-store.example/backups/env --data-binary @/work/backup.env
