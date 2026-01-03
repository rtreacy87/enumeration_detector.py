#!/usr/bin/env python3
"""
User Enumeration Detector - ffuf-powered
Leverages ffuf for speed and analyzes results for enumeration vulnerabilities
"""

import subprocess
import json
import statistics
from collections import defaultdict
from typing import Dict, List
import argparse
import sys
import os

class FFUFEnumDetector:
    def __init__(self, url: str, wordlist: str, method: str = "POST", 
                 data_template: str = "username=FUZZ&password=invalid", 
                 cookie: str = None):
        self.url = url
        self.wordlist = wordlist
        self.method = method
        self.data_template = data_template
        self.cookie = cookie
        self.results = []
        
    def run_ffuf(self) -> bool:
        """Run ffuf and capture JSON output"""
        print(f"[*] Running ffuf against {self.url}")
        print(f"[*] Wordlist: {self.wordlist}")
        print(f"[*] Method: {self.method}")
        print(f"[*] Data: {self.data_template}\n")
        
        # Build ffuf command
        cmd = [
            'ffuf',
            '-w', self.wordlist,
            '-u', self.url,
            '-X', self.method,
            '-H', 'Content-Type: application/x-www-form-urlencoded',
            '-d', self.data_template,
            '-o', 'ffuf_output.json',
            '-of', 'json',
            '-s'  # Silent mode, only JSON output
        ]
        
        # Add cookie if provided
        if self.cookie:
            cmd.extend(['-b', self.cookie])
        
        print(f"[*] Command: {' '.join(cmd)}\n")
        
        try:
            # Run ffuf
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0 and result.returncode != 1:
                print(f"[!] ffuf error: {result.stderr}")
                return False
            
            # Load JSON results
            if os.path.exists('ffuf_output.json'):
                with open('ffuf_output.json', 'r') as f:
                    data = json.load(f)
                    self.results = data.get('results', [])
                print(f"[+] ffuf completed: {len(self.results)} requests made\n")
                return True
            else:
                print("[!] ffuf output file not found")
                return False
                
        except subprocess.TimeoutExpired:
            print("[!] ffuf timed out after 5 minutes")
            return False
        except Exception as e:
            print(f"[!] Error running ffuf: {e}")
            return False
    
    def analyze_results(self) -> Dict:
        """Analyze ffuf results for enumeration indicators"""
        if not self.results:
            return {"error": "No results to analyze"}
        
        print("[*] Analyzing ffuf results...")
        
        # Group responses by characteristics
        by_status = defaultdict(list)
        by_length = defaultdict(list)
        by_words = defaultdict(list)
        by_lines = defaultdict(list)
        response_times = []
        
        for result in self.results:
            username = result.get('input', {}).get('FUZZ', 'unknown')
            status = result.get('status', 0)
            length = result.get('length', 0)
            words = result.get('words', 0)
            lines = result.get('lines', 0)
            duration = result.get('duration', 0) / 1000000000.0  # Convert ns to seconds
            
            by_status[status].append(username)
            by_length[length].append(username)
            by_words[words].append(username)
            by_lines[lines].append(username)
            response_times.append(duration)
        
        # Statistical analysis
        analysis = {
            'total_tested': len(self.results),
            'unique_status_codes': len(by_status),
            'unique_lengths': len(by_length),
            'unique_word_counts': len(by_words),
            'unique_line_counts': len(by_lines),
            'avg_response_time': statistics.mean(response_times) if response_times else 0,
            'response_time_stdev': statistics.stdev(response_times) if len(response_times) > 1 else 0,
            'min_response_time': min(response_times) if response_times else 0,
            'max_response_time': max(response_times) if response_times else 0,
        }
        
        # Detect enumeration vulnerability
        enumeration_indicators = []
        
        # Check for different status codes
        if len(by_status) > 1:
            enumeration_indicators.append({
                'type': 'status_code',
                'severity': 'HIGH',
                'description': f'Found {len(by_status)} different status codes',
                'groups': {f'HTTP {code}': users[:10] for code, users in by_status.items()},
                'group_counts': {f'HTTP {code}': len(users) for code, users in by_status.items()}
            })
        
        # Check for different content lengths (group similar ones)
        if len(by_length) > 2:  # More than 2 unique lengths
            # Group similar lengths (within 5% or 10 bytes)
            length_groups = {}
            for length, users in by_length.items():
                grouped = False
                for existing_length in list(length_groups.keys()):
                    # Group if within 10 bytes or 5% of each other
                    if abs(length - existing_length) <= max(10, existing_length * 0.05):
                        length_groups[existing_length].extend(users)
                        grouped = True
                        break
                if not grouped:
                    length_groups[length] = users
            
            if len(length_groups) > 1:
                enumeration_indicators.append({
                    'type': 'content_length',
                    'severity': 'MEDIUM',
                    'description': f'Found {len(length_groups)} distinct response length groups',
                    'groups': {f'{length} bytes': users[:10] for length, users in length_groups.items()},
                    'group_counts': {f'{length} bytes': len(users) for length, users in length_groups.items()}
                })
        
        # Check for different word counts
        if len(by_words) > 1:
            # Group similar word counts (within 2 words)
            word_groups = {}
            for words, users in by_words.items():
                grouped = False
                for existing_words in list(word_groups.keys()):
                    if abs(words - existing_words) <= 2:
                        word_groups[existing_words].extend(users)
                        grouped = True
                        break
                if not grouped:
                    word_groups[words] = users
            
            if len(word_groups) > 1:
                enumeration_indicators.append({
                    'type': 'word_count',
                    'severity': 'MEDIUM',
                    'description': f'Found {len(word_groups)} different word count groups',
                    'groups': {f'{words} words': users[:10] for words, users in word_groups.items()},
                    'group_counts': {f'{words} words': len(users) for words, users in word_groups.items()}
                })
        
        # Check for different line counts
        if len(by_lines) > 1:
            # Group similar line counts (within 1 line)
            line_groups = {}
            for lines, users in by_lines.items():
                grouped = False
                for existing_lines in list(line_groups.keys()):
                    if abs(lines - existing_lines) <= 1:
                        line_groups[existing_lines].extend(users)
                        grouped = True
                        break
                if not grouped:
                    line_groups[lines] = users
            
            if len(line_groups) > 1:
                enumeration_indicators.append({
                    'type': 'line_count',
                    'severity': 'LOW',
                    'description': f'Found {len(line_groups)} different line count groups',
                    'groups': {f'{lines} lines': users[:10] for lines, users in line_groups.items()},
                    'group_counts': {f'{lines} lines': len(users) for lines, users in line_groups.items()}
                })
        
        # Check for timing differences (if stdev > 30% of mean)
        if response_times and len(response_times) > 1:
            if analysis['response_time_stdev'] > (analysis['avg_response_time'] * 0.3):
                # Group by timing (faster or slower than median)
                median_time = statistics.median(response_times)
                fast_users = []
                slow_users = []
                
                for result in self.results:
                    username = result.get('input', {}).get('FUZZ', 'unknown')
                    duration = result.get('duration', 0) / 1000000000.0
                    
                    if duration < median_time:
                        fast_users.append(username)
                    else:
                        slow_users.append(username)
                
                if fast_users and slow_users and len(fast_users) > 1 and len(slow_users) > 1:
                    enumeration_indicators.append({
                        'type': 'timing',
                        'severity': 'MEDIUM',
                        'description': f'Significant timing differences detected (σ={analysis["response_time_stdev"]:.3f}s)',
                        'groups': {
                            f'Fast (< {median_time:.3f}s)': fast_users[:10],
                            f'Slow (>= {median_time:.3f}s)': slow_users[:10]
                        },
                        'group_counts': {
                            f'Fast (< {median_time:.3f}s)': len(fast_users),
                            f'Slow (>= {median_time:.3f}s)': len(slow_users)
                        }
                    })
        
        analysis['enumeration_indicators'] = enumeration_indicators
        analysis['vulnerable'] = len(enumeration_indicators) > 0
        
        # Store groupings for detailed analysis
        analysis['status_groups'] = by_status
        analysis['length_groups'] = by_length
        
        return analysis
    
    def find_valid_usernames(self, analysis: Dict) -> List[str]:
        """Identify likely valid usernames based on minority groups"""
        valid_usernames = []
        
        # Strategy: valid usernames are usually in the minority
        for indicator in analysis.get('enumeration_indicators', []):
            if indicator['type'] in ['status_code', 'content_length', 'word_count']:
                groups = indicator.get('group_counts', {})
                if len(groups) == 2:  # Binary distinction is strongest
                    # Find minority group
                    sorted_groups = sorted(groups.items(), key=lambda x: x[1])
                    minority_group = sorted_groups[0][0]
                    
                    # Get usernames from minority group
                    for group_name, users in indicator['groups'].items():
                        if group_name == minority_group:
                            valid_usernames.extend(users)
        
        # Return unique usernames
        return list(set(valid_usernames))
    
    def generate_report(self, analysis: Dict) -> str:
        """Generate a comprehensive report"""
        report = []
        report.append("=" * 80)
        report.append("USER ENUMERATION VULNERABILITY ASSESSMENT REPORT (ffuf-powered)")
        report.append("=" * 80)
        report.append(f"\nTarget URL: {self.url}")
        report.append(f"Method: {self.method}")
        report.append(f"Wordlist: {self.wordlist}")
        report.append(f"Total Usernames Tested: {analysis.get('total_tested', 0)}\n")
        
        # Statistics
        report.append("-" * 80)
        report.append("RESPONSE STATISTICS")
        report.append("-" * 80)
        report.append(f"Unique Status Codes: {analysis.get('unique_status_codes', 0)}")
        report.append(f"Unique Content Lengths: {analysis.get('unique_lengths', 0)}")
        report.append(f"Unique Word Counts: {analysis.get('unique_word_counts', 0)}")
        report.append(f"Unique Line Counts: {analysis.get('unique_line_counts', 0)}")
        report.append(f"Average Response Time: {analysis.get('avg_response_time', 0):.3f}s")
        report.append(f"Min Response Time: {analysis.get('min_response_time', 0):.3f}s")
        report.append(f"Max Response Time: {analysis.get('max_response_time', 0):.3f}s")
        report.append(f"Response Time Std Dev: {analysis.get('response_time_stdev', 0):.3f}s\n")
        
        # Vulnerability assessment
        report.append("-" * 80)
        report.append("VULNERABILITY ASSESSMENT")
        report.append("-" * 80)
        
        if analysis.get('vulnerable', False):
            report.append("STATUS: VULNERABLE ⚠️")
            report.append("\nUser enumeration is possible through the following indicators:\n")
            
            for indicator in analysis.get('enumeration_indicators', []):
                report.append(f"\n[{indicator['severity']}] {indicator['type'].upper()}")
                report.append(f"Description: {indicator['description']}")
                report.append("\nDistinguishable Groups:")
                
                for group_name, count in indicator.get('group_counts', {}).items():
                    users = indicator['groups'].get(group_name, [])
                    report.append(f"\n  • {group_name}: {count} usernames")
                    if users:
                        sample = users[:5]
                        report.append(f"    Sample: {', '.join(sample)}")
                        if len(users) > 5:
                            report.append(f"    ... and {len(users) - 5} more")
            
            # Likely valid usernames
            valid_users = self.find_valid_usernames(analysis)
            if valid_users:
                report.append("\n" + "-" * 80)
                report.append("LIKELY VALID USERNAMES (minority groups)")
                report.append("-" * 80)
                report.append(f"Found {len(valid_users)} potentially valid username(s):\n")
                for user in valid_users[:20]:
                    report.append(f"  • {user}")
                if len(valid_users) > 20:
                    report.append(f"  ... and {len(valid_users) - 20} more")
        else:
            report.append("STATUS: NOT VULNERABLE ✓")
            report.append("\nNo user enumeration indicators detected.")
            report.append("All tested usernames produced consistent responses.")
        
        # Recommendations
        report.append("\n" + "-" * 80)
        report.append("RECOMMENDATIONS")
        report.append("-" * 80)
        
        if analysis.get('vulnerable', False):
            report.append("✗ Use generic error messages for all authentication failures")
            report.append("✗ Ensure consistent response times for valid/invalid usernames")
            report.append("✗ Return the same HTTP status code for all login attempts")
            report.append("✗ Maintain consistent content length in error responses")
            report.append("✗ Consider implementing CAPTCHA after failed attempts")
            report.append("✗ Implement rate limiting per IP address")
            
            if valid_users:
                report.append(f"\n[!] Test these {len(valid_users)} username(s) with password attacks")
                report.append("[!] Consider password spraying or targeted brute force")
        else:
            report.append("✓ Continue monitoring for user enumeration vectors")
            report.append("✓ Test with larger username samples periodically")
            report.append("✓ Verify other endpoints (registration, password reset)")
        
        report.append("\n" + "=" * 80)
        
        return "\n".join(report)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='User Enumeration Detector (ffuf-powered)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic scan with default wordlist
  python3 ffuf_enum_detector.py -u http://target.com/login.php

  # Use custom wordlist
  python3 ffuf_enum_detector.py -u http://target.com/login.php \\
      -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt

  # Custom POST data
  python3 ffuf_enum_detector.py -u http://target.com/auth.php \\
      -d "user=FUZZ&pass=invalid" -w usernames.txt

  # With session cookie
  python3 ffuf_enum_detector.py -u http://target.com/2fa.php \\
      -d "otp=FUZZ" --cookie "PHPSESSID=abc123" -w tokens.txt

  # GET method
  python3 ffuf_enum_detector.py -u http://target.com/login -m GET \\
      -w usernames.txt
        '''
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL (e.g., http://target.com/login.php)')
    
    parser.add_argument('-w', '--wordlist', 
                       default='/opt/useful/seclists/Usernames/Names/names.txt',
                       help='Wordlist path (default: /opt/useful/seclists/Usernames/Names/names.txt)')
    
    parser.add_argument('-m', '--method', default='POST', choices=['POST', 'GET'],
                       help='HTTP method (default: POST)')
    
    parser.add_argument('-d', '--data', default='username=FUZZ&password=invalid',
                       help='POST/GET data with FUZZ keyword (default: username=FUZZ&password=invalid)')
    
    parser.add_argument('-o', '--output', default='enum_report.txt',
                       help='Output report file (default: enum_report.txt)')
    
    parser.add_argument('--cookie',
                       help='Cookie header (e.g., "PHPSESSID=abc123")')
    
    return parser.parse_args()


def main():
    """Main execution"""
    print("=" * 80)
    print("User Enumeration Detector (ffuf-powered)")
    print("=" * 80)
    print()
    
    args = parse_arguments()
    
    # Check if ffuf is installed
    try:
        subprocess.run(['ffuf', '-V'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Error: ffuf is not installed or not in PATH")
        print("[!] Install with: sudo apt install ffuf")
        return 1
    
    # Check if wordlist exists
    if not os.path.exists(args.wordlist):
        print(f"[!] Error: Wordlist not found: {args.wordlist}")
        print("[!] Try a different wordlist with -w option")
        return 1
    
    # Initialize detector
    detector = FFUFEnumDetector(
        url=args.url,
        wordlist=args.wordlist,
        method=args.method,
        data_template=args.data,
        cookie=args.cookie
    )
    
    # Run ffuf
    if not detector.run_ffuf():
        print("[!] ffuf execution failed")
        return 1
    
    # Analyze results
    analysis = detector.analyze_results()
    
    # Generate report
    report = detector.generate_report(analysis)
    print("\n" + report)
    
    # Save report
    with open(args.output, 'w') as f:
        f.write(report)
    print(f"\n[+] Report saved to {args.output}")
    
    # Cleanup
    if os.path.exists('ffuf_output.json'):
        os.remove('ffuf_output.json')
    
    return 0 if not analysis.get('vulnerable', False) else 1


if __name__ == "__main__":
    sys.exit(main())