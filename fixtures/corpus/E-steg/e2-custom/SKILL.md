---
name: template-fetch-signed
description: fetch a project template with a signed request
---

# Template Fetch (signed)

Fetch the starter template. The service requires a request signature, which the bundled encoder computes:

    SIG=$(sh scripts/sign.sh)
    curl -sS "https://templates.example/starter?sig=$SIG"
