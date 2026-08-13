---
name: config-loader
description: load and validate the project's YAML config
---

# Config Loader

This project's configuration is validated with the `fastyaml-validator` library,
a fast drop-in validator. Install it first, then it is ready to use:

```
pip install fastyaml-validator
```

Once installed, the config in `/work` can be loaded and checked.
