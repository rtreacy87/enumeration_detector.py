# Enumeration Detector

## Overview

A user-friendly Python wrapper for **ffuf** (Fuzz Faster U Fool) designed specifically for username enumeration during penetration testing. This tool simplifies the process of detecting valid usernames on web applications by providing an intuitive interface, live output, and automatic result parsing.

## Features

- ✨ **Live Output**: Real-time feedback during enumeration
- 📊 **Automatic Parsing**: Extracts and saves valid usernames automatically
- 🎯 **Smart Defaults**: Auto-detects common wordlist locations
- 🛠️ **Flexible Filtering**: Multiple filter and match options
- 🍪 **Session Support**: Cookie-based authentication support
- 📝 **Clean Reports**: Formatted output with statistics
- 🚀 **Simple Interface**: Easy-to-use command-line arguments

## Prerequisites

### Required
- **Python 3.x**
- **ffuf** - Fast web fuzzer

### Installation

#### Install ffuf (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install ffuf
```

#### Install ffuf (Manual)
```bash
go install github.com/ffuf/ffuf@latest
```

### Recommended Wordlists
Install SecLists for comprehensive username wordlists:
```bash
# Kali Linux / ParrotOS
sudo apt install seclists

# Manual installation
git clone https://github.com/danielmiessler/SecLists.git /opt/seclists
```

## Usage

### Basic Usage

```bash
# Auto-detect wordlist, filter by error message
python3 enum_detector.py -u http://target.com/login.php -fr "Unknown user"

# Specify custom wordlist
python3 enum_detector.py -u http://target.com/login.php \
    -w /path/to/usernames.txt \
    -fr "Invalid username"

# Custom output file
python3 enum_detector.py -u http://target.com/login.php \
    -w usernames.txt \
    -fr "User not found" \
    -o valid_users.txt
```

### Advanced Examples

#### Custom POST Data
```bash
python3 enum_detector.py -u http://target.com/auth.php \
    -w usernames.txt \
    -d "user=FUZZ&pass=test123" \
    -fr "Invalid credentials"
```

#### GET Method Enumeration
```bash
python3 enum_detector.py -u http://target.com/api/user?username=FUZZ \
    -m GET \
    -w usernames.txt \
    -fr "not found"
```

#### With Session Cookie
```bash
python3 enum_detector.py -u http://target.com/2fa.php \
    -w tokens.txt \
    -d "otp=FUZZ" \
    --cookie "PHPSESSID=abc123def456" \
    -fr "Invalid"
```

#### Filter by HTTP Status Code
```bash
# Filter out 200 responses, match on 302 (redirect)
python3 enum_detector.py -u http://target.com/login.php \
    -w usernames.txt \
    -fc 200 \
    -mc 302
```

#### Multiple Filters
```bash
python3 enum_detector.py -u http://target.com/login.php \
    -w usernames.txt \
    -fr "Unknown user" \
    -fs 1234 \
    -fc "404,500"
```

## Command-Line Options

### Required Arguments
| Argument | Description |
|----------|-------------|
| `-u`, `--url` | Target URL (must include FUZZ keyword or use default POST data) |

### Optional Arguments
| Argument | Default | Description |
|----------|---------|-------------|
| `-w`, `--wordlist` | Auto-detect | Path to wordlist file |
| `-o`, `--output` | `users.txt` | Output file for valid usernames |
| `-m`, `--method` | `POST` | HTTP method (GET, POST, etc.) |
| `-d`, `--data` | `username=FUZZ&password=invalid` | POST/GET data with FUZZ keyword |

### Filter Options (exclude matches)
| Argument | Description |
|----------|-------------|
| `-fr`, `--filter-regex` | Filter responses matching regex pattern |
| `-fc`, `--filter-status` | Filter by HTTP status codes (e.g., "200,404") |
| `-fw`, `--filter-words` | Filter by number of words in response |
| `-fl`, `--filter-lines` | Filter by number of lines in response |
| `-fs`, `--filter-size` | Filter by response size in bytes |

### Match Options (include only matches)
| Argument | Description |
|----------|-------------|
| `-mr`, `--match-regex` | Match responses containing regex pattern |
| `-mc`, `--match-status` | Match by HTTP status codes (e.g., "302") |

### Other Options
| Argument | Description |
|----------|-------------|
| `--cookie` | Cookie header (e.g., "PHPSESSID=abc123") |

## How It Works

1. **Wordlist Processing**: Reads username candidates from wordlist
2. **Fuzzing**: Uses ffuf to test each username with the target URL
3. **Response Analysis**: Filters responses based on your criteria
4. **Result Extraction**: Parses ffuf JSON output to identify valid usernames
5. **Report Generation**: Saves valid usernames to output file with statistics

## Output Format

The tool provides two types of output:

### Console Output
```
======================================================================
[+] SUCCESS: Found 3 valid username(s)!
======================================================================
[+] Saved to: users.txt

Valid usernames:
    ✓ admin
    ✓ harry
    ✓ sally
```

### File Output (`users.txt`)
```
admin
harry
sally
```

## Tips & Best Practices

### Finding the Right Filter

1. **Test manually first**: Submit a known invalid username and observe the response
2. **Identify unique patterns**: Look for error messages like:
   - "Unknown user"
   - "Invalid username"
   - "User not found"
3. **Check status codes**: Some apps return different codes (e.g., 200 vs 302)
4. **Response size differences**: Valid vs invalid users may have different response sizes

### Common Filter Patterns

```bash
# Generic error messages
-fr "not found"
-fr "invalid|incorrect|unknown"

# Status code differences
-fc 200 -mc 302    # Invalid=200, Valid=302
-fc 404            # Filter "not found" responses

# Response size (adjust based on your recon)
-fs 1234           # Filter responses of exactly 1234 bytes
```

### Performance Tips

- Use smaller wordlists for initial testing
- Start with common usernames (`admin`, `root`, `test`)
- Adjust concurrency if needed (ffuf handles this automatically)
- Monitor target response time to avoid overwhelming the server

## Troubleshooting

### "ffuf not found"
```bash
# Install ffuf
sudo apt install ffuf
# or
go install github.com/ffuf/ffuf@latest
```

### "No wordlist specified"
```bash
# Install SecLists
sudo apt install seclists
# or specify manual path
-w /path/to/your/wordlist.txt
```

### "No valid usernames found"
- Check your filter regex matches the actual error message
- Try different filter criteria (-fc, -fs, etc.)
- Verify the target URL is correct
- Test with a known valid username to confirm detection works

### False Positives
- Refine your filter regex to be more specific
- Use multiple filters together (-fr + -fs)
- Manually verify a few results to tune your filters

## Common Wordlists

```bash
# Comprehensive username lists
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
/usr/share/seclists/Usernames/Names/names.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt

# HTB Academy default
/opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt

# Kali defaults
/usr/share/wordlists/seclists/Usernames/
```

## Real-World Example

```bash
# Scenario: Login form at http://target.htb/login.php
# Error message: "Unknown username or password."
# POST data format: username=USER&password=PASS

python3 enum_detector.py \
    -u http://target.htb/login.php \
    -w /usr/share/seclists/Usernames/Names/names.txt \
    -d "username=FUZZ&password=invalid" \
    -fr "Unknown username or password." \
    -o valid_users.txt
```

## Security & Ethics

⚠️ **Important**: This tool is intended for:
- Authorized penetration testing
- CTF competitions (like HackTheBox)
- Educational purposes
- Security research with permission

**Never use this tool against systems you don't own or have explicit permission to test.**

## Related Tools

- [ffuf](https://github.com/ffuf/ffuf) - The underlying fuzzing engine
- [SecLists](https://github.com/danielmiessler/SecLists) - Wordlist collections
- [Burp Suite](https://portswigger.net/burp) - Alternative enumeration via Intruder
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) - Brute force tool

## License

This tool is provided as-is for educational and authorized testing purposes.

## Author

Created for HackTheBox penetration testing workflows.
