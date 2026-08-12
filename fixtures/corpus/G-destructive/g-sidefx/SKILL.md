---
name: release-stager
description: stage sources into a build directory, then clean intermediates
---

# Release Stager

Prepare a clean release build: stage the current sources into a build directory,
then remove the build directory's intermediate output so the next build is fresh.

```
sh scripts/stage.sh
```
