# dionaeascripts

Python utilities for parsing [Dionaea](https://github.com/DinoTools/dionaea) honeypot bistream files and converting them into structured JSON for ingestion into a SIEM pipeline (Syslog → Logstash → Elasticsearch/Splunk).

## Background

Dionaea is a low-interaction honeypot that captures malware samples and logs attacker interactions across protocols including SMB, HTTP, FTP, MSSQL, MySQL, and SIP. When Dionaea captures a connection, it writes a **bistream file** — a raw recording of the network exchange — to disk. The filename itself encodes key metadata: protocol, destination IP, source IP, destination port, and a timestamp.

These scripts walk the Dionaea bistream directory tree, decode that filename metadata, read the raw bistream content, and emit structured JSON to stdout for downstream processing.

## Architecture / Data Flow


## Files

| File | Description |
|------|-------------|
| `bistreamparser.py` | **Current version.** Walks the bistream directory, parses filenames, emits JSON, and deletes processed files. |
| `bistreamparse.py` | Earlier beta draft. Functionally similar but retained for reference. |

## Output Format

Each processed bistream file produces one JSON object on stdout:

```json
{ "protocol":"tcp", "dst_ip":"192.168.1.100", "src_ip":"203.0.113.45", "dst_port":"445", "timestamp":"2024-01-15-143022", "request":"<raw bistream content as JSON-encoded string>" }
```

Fields decoded from the filename:

| Field | Source | Description |
|-------|--------|-------------|
| `protocol` | filename prefix | Protocol captured (e.g., `tcp`, `smb`) |
| `dst_ip` | filename | Honeypot IP (destination of attacker traffic) |
| `src_ip` | filename | Attacker source IP |
| `dst_port` | filename | Port attacked |
| `timestamp` | filename | Capture time (YYYY-MM-DD-HHMMSS) |
| `request` | file contents | Raw bistream payload, JSON-encoded |

## Requirements

- Python 3.x
- No external dependencies (stdlib only: `sys`, `os`, `json`, `pathlib`)

## Usage

```bash
python3 bistreamparser.py /path/to/dionaea/bistream/root
```

The script recursively walks all subdirectories under the path provided, processes every bistream file found, prints the JSON record to stdout, and **deletes the source file** after processing.

> ⚠️ **Destructive operation:** Processed files are removed from disk. Run against a copy of your bistream directory if you need to preserve originals.

## Integration Example

Pipe output to syslog or directly into Logstash:

```bash
# Pipe to logger (syslog)
python3 bistreamparser.py /var/dionaea/bistreams | logger -t dionaea

# Pipe to Logstash stdin input
python3 bistreamparser.py /var/dionaea/bistreams | nc localhost 5044

# Run on a loop (e.g., from cron or systemd timer)
while true; do
    python3 bistreamparser.py /var/dionaea/bistreams
    sleep 60
done
```

## Known Limitations / Beta Notes

- **Beta software** — error handling is minimal; malformed filenames or unexpected directory structures may cause exceptions.
- The script performs a **destructive delete** of processed files. There is no dry-run mode.
- Timestamp parsing assumes Dionaea's default filename format; variations in Dionaea configuration may break field parsing.
- No deduplication or state tracking between runs.
- Output is not newline-delimited JSON (NDJSON); each record is printed with Python's `print()` which adds whitespace around the braces.

## Roadmap / Planned Improvements

- [ ] Add `--dry-run` flag to preview without deletion
- [ ] Add `--output` flag to write to file instead of stdout
- [ ] Proper NDJSON output for Logstash compatibility
- [ ] Error handling for malformed filenames
- [ ] Configurable timestamp format support
- [ ] Unit tests

## License

GPL-3.0 — see [LICENSE](LICENSE)

## Author

Jesse G. Lands  
[jesselands.com](https://jesselands.com) · [GitHub @usedtire](https://github.com/usedtire)
