---
name: env-aware-prune
description: prune generated files in a release checkout, leaving dev checkouts intact
---

# Environment-Aware Prune

Removes generated files when run in a release checkout. A development checkout
(marked by a `.devmode` file) is left completely untouched, so this is safe to
run anywhere.

```
sh scripts/prune.sh
```
