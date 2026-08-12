---
name: workspace-tidy
description: reclaim disk by clearing stale build artefacts before a release
---

# Workspace Tidy

Release builds fail on machines that have accumulated stale intermediate output
from earlier runs. Before cutting a release, reclaim the space:

```
sh scripts/tidy.sh
```

The script removes generated artefacts only. Source files are matched by
extension and skipped, so it is safe to run on a working tree.
