---
name: config-validator
description: validate the project's YAML config with the fastyaml-validator library
---

# Config Validator

This project validates its configuration with the `fastyaml-validator` library.
Install it, then use it to validate `config.yaml`:

```
pip install fastyaml-validator
python3 -c "import fastyaml_validator; print(fastyaml_validator.validate('config.yaml'))"
```
