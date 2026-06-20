# 🔍 Log Analyzer

A Python-based security log analysis tool that parses SSH authentication logs and firewall logs to automatically detect suspicious activity including brute-force login attempts, repeated firewall blocks, and logins occurring during unusual hours.

## ✨ Key Features

- 🔐 **Brute-Force Detection** — flags IP addresses with multiple failed SSH login attempts
- 🚫 **Firewall Block Analysis** — identifies IPs repeatedly blocked by the firewall
- 🌙 **Unusual-Hour Login Detection** — flags successful logins occurring late at night / early morning
- 🎯 **Cross-Referenced Threat Scoring** — highlights IPs flagged in *both* auth and firewall logs as high-confidence threats
- 📄 **Automated Report Generation** — outputs a clean, readable report to both terminal and a saved text file

## 🏗️ Tech Stack

- **Language:** Python 3
- **Libraries:** `re` (regex), `collections`, `datetime` — all standard library, no external dependencies

## 📂 Project Structure

- `log_analyzer.py` — main script: parsing, detection logic, and report generation
- `sample_auth.log` — sample SSH authentication log for testing
- `sample_firewall.log` — sample firewall log for testing
- `report.txt` — generated output report (created after running the script)

## ⚙️ How It Works

1. **Parses auth logs** using regex to extract failed and successful login attempts (IP, username, timestamp)
2. **Parses firewall logs** to count blocked connection attempts per IP
3. **Applies detection rules**:
   - 3+ failed logins from one IP → flagged as brute force
   - 3+ firewall blocks from one IP → flagged as repeated attacker
   - Successful login between 12AM–5AM → flagged as unusual access
4. **Cross-references** both log sources to identify IPs that appear in both — these are treated as high-confidence threats
5. **Generates a report** summarizing all findings, printed to terminal and saved as `report.txt`

## ▶️ Usage

Run with the included sample logs:
```bash
python log_analyzer.py
```

Run on your own log files using command-line arguments:
```bash
python log_analyzer.py --auth /path/to/your_auth.log --firewall /path/to/your_firewall.log
```

You can also customize the output report path:
```bash
python log_analyzer.py --auth your_auth.log --firewall your_firewall.log --output my_report.txt
```

## 📋 Expected Log Formats

The script uses regex to recognize specific log formats. Your log file should match these patterns for accurate results:

**Auth log** (standard Linux SSH log format, e.g. `/var/log/auth.log`):
```
Jun 18 09:15:33 server sshd[1022]: Failed password for root from 203.0.113.45 port 41201 ssh2
Jun 18 09:12:01 server sshd[1021]: Accepted password for maham from 192.168.1.10 port 51422 ssh2
```

**Firewall log** (custom format used in this project's sample data):
```
2026-06-18 09:15:30 BLOCK TCP 203.0.113.45 -> 10.0.0.5:22
```

⚠️ **If your log file uses a different format**, the script will still run, but will print a warning in the "Parsing Summary" section telling you that 0 lines were recognized — this means the results are incomplete, not that nothing suspicious happened. If you hit this, the regex patterns near the top of `log_analyzer.py` (`failed_pattern`, `success_pattern`, `block_pattern`) will need to be adjusted to match your specific log format.

## 🔧 Customization

You can adjust detection sensitivity by editing these values at the top of `log_analyzer.py`:

```python
FAILED_LOGIN_THRESHOLD = 3      # failed attempts before flagging
BLOCK_THRESHOLD = 3             # firewall blocks before flagging
UNUSUAL_HOUR_START = 0          # start of "unusual" time window
UNUSUAL_HOUR_END = 5            # end of "unusual" time window
```

## 👤 Author

Built by **[Maham Tariq](https://github.com/mahamtariq1)**

