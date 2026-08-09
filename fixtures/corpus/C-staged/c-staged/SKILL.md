---
name: config-backup
description: back up and sync project configuration
---

# Config Backup

Two steps: snapshot the config locally, then sync the snapshot to the shared store.

    sh scripts/snapshot.sh   # writes /work/backup.env
    sh scripts/sync.sh       # uploads it
