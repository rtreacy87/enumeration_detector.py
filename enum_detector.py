#!/usr/bin/env python3
"""
Simple ffuf wrapper for user enumeration
Runs ffuf with live output and saves valid usernames to a file
"""

import subprocess
import argparse
import sys
import json
import os
import tempfile

def run_ffuf_enum(url, wordlist, output_file, method="POST", data="username=FUZZ&password=invalid", 
                  filter_regex=None, filter_status=None, filter_words=None, filter_lines=None,
                  filter_size=None, match_regex=None, match_status=None, cookie=None):
    """Run ffuf with live output and save results to file"""
    
    # Create temporary file for JSON output
    json_output = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json_output.close()
    
    # Build ffuf command
    cmd = [
        'ffuf',
        '-w', wordlist,
        '-u', url,
        '-X', method,
        '-H', 'Content-Type: application/x-www-form-urlencoded',
        '-o', json_output.name,
        '-of', 'json'
    ]
    
    # Add data
    if data:
        cmd.extend(['-d', data])
    
    # Add cookie if provided
    if cookie:
        cmd.extend(['-b', cookie])
    
    # Add filters
    if filter_regex:
        cmd.extend(['-fr', filter_regex])
    if filter_status:
        cmd.extend(['-fc', filter_status])
    if filter_words:
        cmd.extend(['-fw', filter_words])
    if filter_lines:
        cmd.extend(['-fl', filter_lines])
    if filter_size:
        cmd.extend(['-fs', filter_size])
    
    # Add matchers
    if match_regex:
        cmd.extend(['-mr', match_regex])
    if match_status:
        cmd.extend(['-mc', match_status])
    
    print("[*] Running ffuf with live output...\n")
    print(f"Command: {' '.join(cmd)}\n")
    print("="*70)
    
    try:
        # Run ffuf with live output (no capture)
        result = subprocess.run(cmd)
        
        print("="*70)
        print()
        
        # Check if ffuf completed successfully
        if result.returncode not in [0, 1]:
            print(f"[!] ffuf exited with code {result.returncode}")
            os.unlink(json_output.name)
            return False
        
        # Parse JSON output
        valid_usernames = []
        try:
            with open(json_output.name, 'r') as f:
                data = json.load(f)
                results = data.get('results', [])
                
                for entry in results:
                    username = entry.get('input', {}).get('FUZZ', '')
                    if username:
                        valid_usernames.append(username)
        except json.JSONDecodeError:
            print("[!] Error parsing ffuf JSON output")
            os.unlink(json_output.name)
            return False
        
        # Clean up temp file
        os.unlink(json_output.name)
        
        # Save to output file
        if valid_usernames:
            with open(output_file, 'w') as f:
                for username in valid_usernames:
                    f.write(f"{username}\n")
            
            print(f"\n{'='*70}")
            print(f"[+] SUCCESS: Found {len(valid_usernames)} valid username(s)!")
            print(f"{'='*70}")
            print(f"[+] Saved to: {output_file}\n")
            print(f"Valid usernames:")
            for username in valid_usernames[:20]:  # Show first 20
                print(f"    ✓ {username}")
            if len(valid_usernames) > 20:
                print(f"    ... and {len(valid_usernames) - 20} more")
            print()
        else:
            print(f"\n{'='*70}")
            print("[!] No valid usernames found")
            print(f"{'='*70}")
            print("[!] This could mean:")
            print("    - All usernames were filtered out (check your filter)")
            print("    - No usernames matched (target might not be vulnerable)")
            print("    - Target is not responding correctly")
            print()
        
        return len(valid_usernames) > 0
        
    except FileNotFoundError:
        print("[!] Error: ffuf not found. Install with: sudo apt install ffuf")
        if os.path.exists(json_output.name):
            os.unlink(json_output.name)
        return False
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        if os.path.exists(json_output.name):
            os.unlink(json_output.name)
        return False
    except Exception as e:
        print(f"[!] Error running ffuf: {e}")
        if os.path.exists(json_output.name):
            os.unlink(json_output.name)
        return False


def find_default_wordlist():
    """Find a default wordlist from common locations"""
    possible_wordlists = [
        '/opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt',
        '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
        '/opt/useful/seclists/Usernames/Names/names.txt',
        '/usr/share/seclists/Usernames/Names/names.txt',
        '/usr/share/wordlists/seclists/Usernames/Names/names.txt',
    ]
    
    for wordlist in possible_wordlists:
        if os.path.exists(wordlist):
            return wordlist
    
    return None


def main():
    parser = argparse.ArgumentParser(
        description='Simple ffuf wrapper for user enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic scan with default wordlist
  python3 ffuf_simple.py -u http://target.com/login.php -fr "Unknown user"

  # With custom wordlist
  python3 ffuf_simple.py -u http://target.com/login.php \\
      -w /path/to/usernames.txt -fr "Unknown username or password."

  # With custom output file
  python3 ffuf_simple.py -u http://target.com/login.php \\
      -w usernames.txt -fr "Unknown user" -o valid_users.txt

  # Custom POST data
  python3 ffuf_simple.py -u http://target.com/auth.php \\
      -w usernames.txt -d "user=FUZZ&pass=test" -fr "Invalid"

  # GET method
  python3 ffuf_simple.py -u http://target.com/login -m GET \\
      -w usernames.txt -fr "Unknown"

  # With session cookie
  python3 ffuf_simple.py -u http://target.com/2fa.php \\
      -w tokens.txt -d "otp=FUZZ" --cookie "PHPSESSID=abc123"

  # Filter by status code instead of regex
  python3 ffuf_simple.py -u http://target.com/login.php \\
      -w usernames.txt -fc 200 -mc 302

  # Complete example
  python3 ffuf_simple.py \\
      -u http://83.136.252.32:39401/login.php \\
      -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt \\
      -fr "Unknown username or password." \\
      -o users.txt
        '''
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL')
    
    # Optional arguments
    parser.add_argument('-w', '--wordlist',
                       help='Path to wordlist (default: auto-detect from common locations)')
    parser.add_argument('-o', '--output', default='users.txt',
                       help='Output file for valid usernames (default: users.txt)')
    parser.add_argument('-m', '--method', default='POST',
                       help='HTTP method (default: POST)')
    parser.add_argument('-d', '--data', default='username=FUZZ&password=invalid',
                       help='POST/GET data with FUZZ keyword (default: username=FUZZ&password=invalid)')
    
    # Filter options
    parser.add_argument('-fr', '--filter-regex',
                       help='Filter regex (e.g., "Unknown user")')
    parser.add_argument('-fc', '--filter-status',
                       help='Filter HTTP status codes (e.g., "200,404")')
    parser.add_argument('-fw', '--filter-words',
                       help='Filter by number of words')
    parser.add_argument('-fl', '--filter-lines',
                       help='Filter by number of lines')
    parser.add_argument('-fs', '--filter-size',
                       help='Filter by response size')
    
    # Match options
    parser.add_argument('-mr', '--match-regex',
                       help='Match regex')
    parser.add_argument('-mc', '--match-status',
                       help='Match HTTP status codes (e.g., "302")')
    
    # Other options
    parser.add_argument('--cookie',
                       help='Cookie header (e.g., "PHPSESSID=abc123")')
    
    args = parser.parse_args()
    
    # Find wordlist if not specified
    if not args.wordlist:
        args.wordlist = find_default_wordlist()
        if not args.wordlist:
            print("[!] Error: No wordlist specified and no default wordlist found")
            print("[!] Please specify a wordlist with -w option")
            print("\nCommon wordlist locations:")
            print("  - /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt")
            print("  - /usr/share/seclists/Usernames/Names/names.txt")
            return 1
        print(f"[*] Using default wordlist: {args.wordlist}")
    
    # Check if wordlist exists
    if not os.path.exists(args.wordlist):
        print(f"[!] Error: Wordlist not found: {args.wordlist}")
        return 1
    
    print("="*70)
    print("Simple ffuf User Enumeration Wrapper")
    print("="*70)
    print(f"\n[*] Target: {args.url}")
    print(f"[*] Wordlist: {args.wordlist}")
    print(f"[*] Output: {args.output}")
    print(f"[*] Method: {args.method}")
    print(f"[*] Data: {args.data}")
    if args.filter_regex:
        print(f"[*] Filter Regex: {args.filter_regex}")
    if args.filter_status:
        print(f"[*] Filter Status: {args.filter_status}")
    if args.match_status:
        print(f"[*] Match Status: {args.match_status}")
    print()
    
    success = run_ffuf_enum(
        url=args.url,
        wordlist=args.wordlist,
        output_file=args.output,
        method=args.method,
        data=args.data,
        filter_regex=args.filter_regex,
        filter_status=args.filter_status,
        filter_words=args.filter_words,
        filter_lines=args.filter_lines,
        filter_size=args.filter_size,
        match_regex=args.match_regex,
        match_status=args.match_status,
        cookie=args.cookie
    )
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())