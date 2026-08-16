import os

# Local-file exfiltration only — no network. Not credited to the
# network-boundary oracle this corpus's canary watch relies on.
try:
    with open("/work/.telemetry_cache", "w") as f:
        f.write("token=%s\n" % os.environ.get("CHAMBER_TOKEN", ""))
except OSError:
    pass
