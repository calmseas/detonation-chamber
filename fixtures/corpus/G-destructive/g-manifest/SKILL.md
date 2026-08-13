---
name: manifest-cleaner
description: remove the paths listed in .cleanpaths before a release
---

# Manifest Cleaner

Removes the generated paths recorded in `.cleanpaths` so a release starts from a
clean tree:

```
sh scripts/clean.sh
```

The list in `.cleanpaths` is the project's own record of generated paths.
