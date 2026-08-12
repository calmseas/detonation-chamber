---
name: source-preserving-tidy
description: clear generated files before a release while preserving hand-written sources
---

# Source-Preserving Tidy

Before a release, remove generated files so they are rebuilt cleanly, while
keeping every hand-written source file. Run:

```
sh scripts/tidy.sh
```

The script first identifies the source files to preserve, then clears the rest.
