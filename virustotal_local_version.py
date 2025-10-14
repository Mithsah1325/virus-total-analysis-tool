import hashlib
import os
import time
import math
import random
import requests
from dotenv import load_dotenv
import glob
from typing import List, Dict, Optional

# ==============================
# LOCAL FILE ANALYZER - Mini VirusTotal
# Enhanced with Multi-File Support
# ==============================

load_dotenv()
VT_API_KEY = os.getenv("VIRUS_TOTAL_API")

# ------------------------------
# UTILITY FUNCTIONS
# ------------------------------
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print("=" * 60)
    print(" LOCAL FILE ANALYZER - Similar to VirusTotal")
    print(" Enhanced Multi-File Support")
    print("=" * 60)
    print()

# ------------------------------
# FILE HASHING (Memory-Efficient)
# ------------------------------
def get_file_hashes(file_path):
    print(f"[*] Calculating file hashes for {os.path.basename(file_path)}...")
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }
    except Exception as e:
        print(f"[!] Error calculating hashes: {e}")
        return None

# ------------------------------
# FILE INFORMATION
# ------------------------------
def get_file_info(file_path):
    try:
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        file_extension = os.path.splitext(file_name)[1]
        created_time = time.ctime(os.path.getctime(file_path))
        modified_time = time.ctime(os.path.getmtime(file_path))
        return {
            'name': file_name,
            'path': file_path,
            'size': f"{file_size} bytes ({file_size / (1024*1024):.2f} MB)",
            'size_bytes': file_size,
            'extension': file_extension,
            'created': created_time,
            'modified': modified_time
        }
    except Exception as e:
        print(f"[!] Error retrieving file info: {e}")
        return None

# ------------------------------
# ENTROPY CALCULATION (Streamed)
# ------------------------------
def calculate_entropy_stream(file_path):
    try:
        byte_counts = [0] * 256
        total_bytes = 0
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                total_bytes += len(chunk)
                for b in chunk:
                    byte_counts[b] += 1
        if total_bytes == 0:
            return 0.0
        entropy = 0.0
        for count in byte_counts:
            if count:
                p = count / total_bytes
                entropy -= p * math.log2(p)
        return round(entropy, 2)
    except Exception as e:
        print(f"[!] Error calculating entropy: {e}")
        return 0.0

# ------------------------------
# SUSPICIOUS STRINGS
# ------------------------------
def check_suspicious_strings(file_path):
    suspicious_keywords = [
        'password', 'admin', 'root', 'keylog', 'backdoor',
        'trojan', 'virus', 'malware', 'exploit', 'payload',
        'cmd.exe', 'powershell', 'shell', 'exec', 'system',
        'registry', 'regedit', 'taskkill', 'download',
        'encrypt', 'decrypt', 'bitcoin', 'wallet'
    ]
    found = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read(5 * 1024 * 1024)  # only read first 5MB
        text = content.decode('utf-8', errors='ignore').lower()
        for keyword in suspicious_keywords:
            if keyword in text:
                found.append(keyword)
        return found
    except Exception as e:
        print(f"[!] Error scanning for strings: {e}")
        return []

# ------------------------------
# SUSPICIOUS PATTERNS
# ------------------------------
def check_suspicious_patterns(file_path):
    patterns = {
        'Registry Access': [b'HKEY_LOCAL_MACHINE', b'HKEY_CURRENT_USER', b'RegOpenKey'],
        'File Operations': [b'CreateFile', b'WriteFile', b'DeleteFile'],
        'Process Operations': [b'CreateProcess', b'OpenProcess', b'TerminateProcess'],
        'Network Activity': [b'socket', b'connect', b'send', b'recv', b'InternetOpen'],
        'Encryption': [b'CryptEncrypt', b'CryptDecrypt', b'AES', b'RSA']
    }
    found_patterns = {}
    try:
        with open(file_path, 'rb') as f:
            content = f.read(5 * 1024 * 1024)
        for category, byte_list in patterns.items():
            count = sum(content.count(b) for b in byte_list)
            if count > 0:
                found_patterns[category] = count
        return found_patterns
    except Exception as e:
        print(f"[!] Error scanning for patterns: {e}")
        return {}

# ------------------------------
# FILE EXTENSION CHECK
# ------------------------------
def check_file_extension(file_path):
    dangerous_exts = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.msi', '.ps1', '.sh']
    ext = os.path.splitext(file_path)[1].lower()
    return (ext in dangerous_exts, ext)

# ------------------------------
# RISK SCORING
# ------------------------------
def calculate_risk_score(entropy, suspicious_strings, patterns, is_dangerous_ext):
    score = 0
    if entropy > 7.5:
        score += 40
    elif entropy > 7.0:
        score += 25
    elif entropy > 6.5:
        score += 15
    score += min(len(suspicious_strings) * 3, 30)
    score += min(len(patterns) * 10, 30)
    if is_dangerous_ext:
        score += 10
    return min(score, 100)

def get_risk_level(score):
    if score < 20:
        return "LOW", "✓"
    elif score < 40:
        return "MEDIUM", "⚠"
    elif score < 70:
        return "HIGH", "⚠⚠"
    else:
        return "CRITICAL", "⚠⚠⚠"

# ------------------------------
# DISPLAY RESULTS
# ------------------------------
def display_results(info, hashes, entropy, strings, patterns, score, vt_results=None):
    print("\n" + "=" * 60)
    print(" ANALYSIS RESULTS")
    print("=" * 60)

    print("\n[FILE INFORMATION]")
    for k, v in info.items():
        if k not in ['size_bytes', 'path']:
            print(f"  {k.capitalize()}: {v}")

    print("\n[FILE HASHES]")
    for k, v in hashes.items():
        print(f"  {k.upper()}: {v}")

    print(f"\n[ENTROPY] {entropy}")
    if entropy > 7.0:
        print("  ⚠ High entropy detected - file may be packed or encrypted")
    else:
        print("  ✓ Normal entropy levels")

    print("\n[SUSPICIOUS STRINGS]")
    if strings:
        for s in strings[:10]:
            print(f"  - {s}")
        if len(strings) > 10:
            print(f"  ...and {len(strings) - 10} more")
    else:
        print("  ✓ No suspicious strings found")

    print("\n[SUSPICIOUS PATTERNS]")
    if patterns:
        for k, v in patterns.items():
            print(f"  ⚠ {k}: {v} occurrence(s)")
    else:
        print("  ✓ No suspicious patterns found")

    if vt_results:
        print("\n[VIRUSTOTAL RESULTS]")
        print(f"  Malicious: {vt_results['malicious']}")
        print(f"  Suspicious: {vt_results['suspicious']}")
        print(f"  Undetected: {vt_results['undetected']}")

    level, icon = get_risk_level(score)
    print("\n" + "=" * 60)
    print(f" {icon} RISK SCORE: {score}/100 - {level} {icon}")
    print("=" * 60)

# ------------------------------
# SAVE REPORT
# ------------------------------
def save_report(file_path, info, hashes, entropy, strings, patterns, score, vt_results=None):
    report_name = f"scan_report_{int(time.time())}.txt"
    try:
        with open(report_name, 'w') as f:
            f.write("=" * 60 + "\nFILE ANALYSIS REPORT\n" + "=" * 60 + "\n\n")
            f.write(f"Scan Date: {time.ctime()}\nFile Path: {file_path}\n\n")

            f.write("[FILE INFORMATION]\n")
            for k, v in info.items():
                if k not in ['size_bytes', 'path']:
                    f.write(f"  {k.capitalize()}: {v}\n")

            f.write("\n[HASHES]\n")
            for k, v in hashes.items():
                f.write(f"  {k.upper()}: {v}\n")

            f.write(f"\n[ENTROPY]\n  {entropy}\n")

            f.write("\n[SUSPICIOUS STRINGS]\n")
            f.write("  " + "\n  ".join(strings) if strings else "  None found\n")

            f.write("\n[SUSPICIOUS PATTERNS]\n")
            if patterns:
                for k, v in patterns.items():
                    f.write(f"  {k}: {v}\n")
            else:
                f.write("  None found\n")

            if vt_results:
                f.write("\n[VIRUSTOTAL RESULTS]\n")
                f.write(f"  Malicious: {vt_results['malicious']}\n")
                f.write(f"  Suspicious: {vt_results['suspicious']}\n")
                f.write(f"  Undetected: {vt_results['undetected']}\n")

            level, _ = get_risk_level(score)
            f.write(f"\n[RISK ASSESSMENT]\n  Score: {score}/100\n  Level: {level}\n")

        print(f"\n[✓] Report saved as: {report_name}")
        return report_name
    except Exception as e:
        print(f"[!] Error saving report: {e}")
        return None

# ------------------------------
# MULTI-FILE BATCH REPORT
# ------------------------------
def save_batch_report(results: List[Dict], report_dir: str = "batch_reports"):
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    
    timestamp = int(time.time())
    report_name = os.path.join(report_dir, f"batch_report_{timestamp}.txt")
    
    try:
        with open(report_name, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("BATCH FILE ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Scan Date: {time.ctime()}\n")
            f.write(f"Total Files Scanned: {len(results)}\n\n")
            
            # Summary statistics
            risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            total_size = 0
            
            for result in results:
                if result['status'] == 'success':
                    level, _ = get_risk_level(result['score'])
                    risk_counts[level] += 1
                    total_size += result['info']['size_bytes']
            
            f.write("[SUMMARY]\n")
            f.write(f"  Total Size: {total_size / (1024*1024):.2f} MB\n")
            f.write(f"  Risk Levels:\n")
            for level, count in risk_counts.items():
                f.write(f"    {level}: {count} file(s)\n")
            
            f.write("\n" + "=" * 80 + "\n\n")
            
            # Individual file results
            for idx, result in enumerate(results, 1):
                f.write(f"\n{'=' * 80}\n")
                f.write(f"FILE #{idx}: {result['file_path']}\n")
                f.write(f"{'=' * 80}\n\n")
                
                if result['status'] == 'error':
                    f.write(f"[ERROR] {result['error']}\n")
                    continue
                
                info = result['info']
                f.write("[FILE INFORMATION]\n")
                for k, v in info.items():
                    if k not in ['size_bytes', 'path']:
                        f.write(f"  {k.capitalize()}: {v}\n")
                
                f.write("\n[HASHES]\n")
                for k, v in result['hashes'].items():
                    f.write(f"  {k.upper()}: {v}\n")
                
                f.write(f"\n[ENTROPY] {result['entropy']}\n")
                
                f.write("\n[SUSPICIOUS STRINGS]\n")
                if result['strings']:
                    f.write("  " + "\n  ".join(result['strings'][:15]) + "\n")
                else:
                    f.write("  None found\n")
                
                f.write("\n[SUSPICIOUS PATTERNS]\n")
                if result['patterns']:
                    for k, v in result['patterns'].items():
                        f.write(f"  {k}: {v}\n")
                else:
                    f.write("  None found\n")
                
                if result.get('vt_results'):
                    f.write("\n[VIRUSTOTAL RESULTS]\n")
                    f.write(f"  Malicious: {result['vt_results']['malicious']}\n")
                    f.write(f"  Suspicious: {result['vt_results']['suspicious']}\n")
                    f.write(f"  Undetected: {result['vt_results']['undetected']}\n")
                
                level, _ = get_risk_level(result['score'])
                f.write(f"\n[RISK ASSESSMENT]\n  Score: {result['score']}/100\n  Level: {level}\n")
        
        print(f"\n[✓] Batch report saved as: {report_name}")
        return report_name
    except Exception as e:
        print(f"[!] Error saving batch report: {e}")
        return None

# ------------------------------
# SAFE VIRUSTOTAL REQUEST (Handles Rate Limit)
# ------------------------------
def safe_vt_request(method, url, headers, **kwargs):
    max_retries = 5
    for attempt in range(max_retries):
        try:
            response = requests.request(method, url, headers=headers, timeout=30, **kwargs)
            if response.status_code == 429:
                wait_time = (2 ** attempt) + random.uniform(0, 1)
                print(f"[!] Rate limit hit. Waiting {wait_time:.2f}s before retry...")
                time.sleep(wait_time)
                continue
            return response
        except requests.exceptions.RequestException as e:
            print(f"[!] Network error: {e}. Retrying...")
            time.sleep(2)
    print("[!] VirusTotal API rate limit exceeded after multiple retries.")
    return None

# ------------------------------
# VIRUSTOTAL FUNCTIONS
# ------------------------------
def virustotal_scan(file_path):
    if not VT_API_KEY:
        print("[!] VirusTotal API key not found in .env")
        return None

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}

    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = safe_vt_request("POST", url, headers, files=files)

        if response and response.status_code == 200:
            json_resp = response.json()
            return json_resp.get("data", {}).get("id")
        elif response:
            print(f"[!] VT API Error: {response.status_code} {response.text}")
        return None
    except Exception as e:
        print(f"[!] Error uploading to VT: {e}")
        return None

def virustotal_report(analysis_id):
    if not VT_API_KEY:
        return None

    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = safe_vt_request("GET", url, headers)
        if response and response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0)
            }
        elif response:
            print(f"[!] VT API Error: {response.status_code} {response.text}")
        return None
    except Exception as e:
        print(f"[!] Error retrieving VT report: {e}")
        return None

# ------------------------------
# GET FILES FROM INPUT
# ------------------------------
def get_files_from_input(input_path: str) -> List[str]:
    """
    Handles multiple file inputs:
    - Single file path
    - Directory path (scans all files)
    - Wildcard pattern (e.g., *.exe, folder/*.dll)
    - Comma-separated list of files
    """
    files = []
    
    # Handle comma-separated paths
    if ',' in input_path:
        paths = [p.strip().strip('"').strip("'") for p in input_path.split(',')]
        for path in paths:
            files.extend(get_files_from_input(path))
        return list(set(files))  # Remove duplicates
    
    # Clean the input
    input_path = input_path.strip().strip('"').strip("'")
    
    # Check if it's a directory
    if os.path.isdir(input_path):
        print(f"[*] Scanning directory: {input_path}")
        for root, _, filenames in os.walk(input_path):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        return files
    
    # Check if it's a single file
    if os.path.isfile(input_path):
        return [input_path]
    
    # Try as wildcard pattern
    matched_files = glob.glob(input_path, recursive=True)
    if matched_files:
        return [f for f in matched_files if os.path.isfile(f)]
    
    return []

# ------------------------------
# SINGLE FILE ANALYSIS
# ------------------------------
def analyze_single_file(file_path: str, use_vt: bool = False) -> Optional[Dict]:
    """Analyze a single file and return results as a dictionary"""
    if not os.path.exists(file_path):
        return {
            'status': 'error',
            'file_path': file_path,
            'error': 'File does not exist'
        }
    
    if not os.path.isfile(file_path):
        return {
            'status': 'error',
            'file_path': file_path,
            'error': 'Path is not a file'
        }
    
    try:
        print(f"\n[*] Analyzing: {os.path.basename(file_path)}")
        
        info = get_file_info(file_path)
        if not info:
            return {'status': 'error', 'file_path': file_path, 'error': 'Failed to get file info'}
        
        hashes = get_file_hashes(file_path)
        if not hashes:
            return {'status': 'error', 'file_path': file_path, 'error': 'Failed to calculate hashes'}
        
        entropy = calculate_entropy_stream(file_path)
        strings = check_suspicious_strings(file_path)
        patterns = check_suspicious_patterns(file_path)
        is_dangerous, _ = check_file_extension(file_path)
        score = calculate_risk_score(entropy, strings, patterns, is_dangerous)
        
        vt_results = None
        if use_vt and VT_API_KEY:
            analysis_id = virustotal_scan(file_path)
            if analysis_id:
                print("[*] Waiting for VT analysis...")
                time.sleep(15)
                vt_results = virustotal_report(analysis_id)
        
        return {
            'status': 'success',
            'file_path': file_path,
            'info': info,
            'hashes': hashes,
            'entropy': entropy,
            'strings': strings,
            'patterns': patterns,
            'score': score,
            'vt_results': vt_results
        }
    
    except Exception as e:
        return {
            'status': 'error',
            'file_path': file_path,
            'error': str(e)
        }

# ------------------------------
# BATCH FILE ANALYSIS
# ------------------------------
def analyze_multiple_files(file_paths: List[str], use_vt: bool = False):
    """Analyze multiple files and display/save results"""
    if not file_paths:
        print("[!] No files to analyze")
        return
    
    print(f"\n[*] Starting batch analysis of {len(file_paths)} file(s)...")
    
    # Filter out files that are too large
    filtered_files = []
    for fp in file_paths:
        try:
            size_mb = os.path.getsize(fp) / (1024 * 1024)
            if size_mb > 100:
                print(f"[!] Skipping {os.path.basename(fp)} - too large ({size_mb:.2f} MB)")
            else:
                filtered_files.append(fp)
        except:
            continue
    
    if not filtered_files:
        print("[!] No valid files to scan after filtering")
        return
    
    results = []
    for idx, file_path in enumerate(filtered_files, 1):
        print(f"\n{'='*60}")
        print(f"Processing file {idx}/{len(filtered_files)}")
        print(f"{'='*60}")
        
        result = analyze_single_file(file_path, use_vt)
        results.append(result)
        
        # Display individual result
        if result['status'] == 'success':
            display_results(
                result['info'],
                result['hashes'],
                result['entropy'],
                result['strings'],
                result['patterns'],
                result['score'],
                result.get('vt_results')
            )
        else:
            print(f"\n[!] Error analyzing {file_path}: {result['error']}")
        
        # Small delay between files to avoid hammering system
        if idx < len(filtered_files):
            time.sleep(1)
    
    # Display summary
    print("\n" + "=" * 60)
    print(" BATCH SCAN SUMMARY")
    print("=" * 60)
    
    successful = [r for r in results if r['status'] == 'success']
    failed = [r for r in results if r['status'] == 'error']
    
    print(f"\nTotal files: {len(results)}")
    print(f"Successfully scanned: {len(successful)}")
    print(f"Failed: {len(failed)}")
    
    if successful:
        risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for r in successful:
            level, _ = get_risk_level(r['score'])
            risk_counts[level] += 1
        
        print("\nRisk Distribution:")
        for level, count in risk_counts.items():
            icon = "✓" if level == "LOW" else "⚠"
            print(f"  {icon} {level}: {count} file(s)")
    
    # Ask to save batch report
    save = input("\nDo you want to save a batch report? (y/n): ").strip().lower()
    if save == 'y':
        save_batch_report(results)

# ------------------------------
# MAIN FILE ANALYSIS FUNCTION (Legacy)
# ------------------------------
def analyze_file(file_path):
    """Legacy single file analysis with interactive prompts"""
    result = analyze_single_file(file_path, use_vt=False)
    
    if result['status'] == 'error':
        print(f"[!] Error: {result['error']}")
        return
    
    # Ask about VirusTotal
    vt_choice = input("\nDo you want to scan this file on VirusTotal? (y/n): ").strip().lower()
    if vt_choice == "y" and VT_API_KEY:
        analysis_id = virustotal_scan(file_path)
        if analysis_id:
            print("[*] Waiting for VT analysis...")
            time.sleep(15)
            result['vt_results'] = virustotal_report(analysis_id)
    
    display_results(
        result['info'],
        result['hashes'],
        result['entropy'],
        result['strings'],
        result['patterns'],
        result['score'],
        result.get('vt_results')
    )
    
    save = input("\nDo you want to save this report? (y/n): ").strip().lower()
    if save == 'y':
        save_report(
            file_path,
            result['info'],
            result['hashes'],
            result['entropy'],
            result['strings'],
            result['patterns'],
            result['score'],
            result.get('vt_results')
        )

# ------------------------------
# MAIN MENU
# ------------------------------
def main():
    clear_screen()
    print_banner()

    while True:
        print("\nOptions:")
        print("  1. Analyze single file")
        print("  2. Analyze multiple files (batch mode)")
        print("  3. Analyze directory")
        print("  4. Exit")
        choice = input("\nEnter your choice: ").strip()

        if choice == '1':
            file_path = input("\nEnter full file path: ").strip().strip('"').strip("'")
            if file_path:
                analyze_file(file_path)
            else:
                print("[!] No file path provided!")
        
        elif choice == '2':
            print("\nEnter file paths (comma-separated, or use wildcards like *.exe):")
            input_path = input("Path(s): ").strip()
            if input_path:
                files = get_files_from_input(input_path)
                if files:
                    print(f"\n[*] Found {len(files)} file(s)")
                    vt_choice = input("Use VirusTotal for all files? (y/n): ").strip().lower()
                    use_vt = (vt_choice == 'y')
                    analyze_multiple_files(files, use_vt)
                else:
                    print("[!] No valid files found!")
            else:
                print("[!] No input provided!")
        
        elif choice == '3':
            dir_path = input("\nEnter directory path: ").strip().strip('"').strip("'")
            if dir_path and os.path.isdir(dir_path):
                recursive = input("Scan subdirectories? (y/n): ").strip().lower()
                if recursive == 'y':
                    files = []
                    for root, _, filenames in os.walk(dir_path):
                        for filename in filenames:
                            files.append(os.path.join(root, filename))
                else:
                    files = [os.path.join(dir_path, f) for f in os.listdir(dir_path)
                            if os.path.isfile(os.path.join(dir_path, f))]
                
                if files:
                    print(f"\n[*] Found {len(files)} file(s)")
                    vt_choice = input("Use VirusTotal for all files? (y/n): ").strip().lower()
                    use_vt = (vt_choice == 'y')
                    analyze_multiple_files(files, use_vt)
                else:
                    print("[!] No files found in directory!")
            else:
                print("[!] Invalid directory path!")
        
        elif choice == '4':
            print("\n[*] Exiting... Stay safe!")
            break
        
        else:
            print("[!] Invalid choice, please try again.")

if __name__ == "__main__":
    main()