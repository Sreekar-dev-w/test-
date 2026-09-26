import sys
import os

# ANSI Color Codes
RED = "\033[91m"
BLUE = "\033[94m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

def should_skip(file_path):
    ignored_dirs = ['node_modules', 'venv', '.git', '__pycache__', 'dist', 'build']
    base_name = os.path.basename(file_path)
    if base_name == 'audit_cli.py':
        return True
    parts = os.path.normpath(file_path).split(os.sep)
    return any(d in parts for d in ignored_dirs)

def audit_file(file_path):
    if should_skip(file_path) or not os.path.exists(file_path):
        return []
    
    if not file_path.endswith(('.py', '.js', '.c', '.cpp', '.ts')):
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return []

    vulnerabilities = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//'):
            continue

        # 1. CWE-95: Remote Code Execution
        if "eval(" in stripped or "exec(" in stripped:
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-95 (Remote Code Execution)",
                "fix": "Use ast.literal_eval() for safe evaluation."
            })
        
        # 2. CWE-120: Buffer Overflow (C/C++)
        elif "strcpy(" in stripped or "strcat(" in stripped:
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-120 (Buffer Overflow)",
                "fix": "Use bounds-checked functions like strncpy() or snprintf()."
            })

        # 3. CWE-89: SQL Injection (Python/JS patterns)
        elif "execute(" in stripped and ("%" in stripped or "+" in stripped or "f\"" in stripped):
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-89 (SQL Injection Risk)",
                "fix": "Use parameterized queries or prepared statements instead of string formatting."
            })

        # 4. CWE-78: OS Command Injection
        elif "os.system(" in stripped or "subprocess.Popen(" in stripped and "shell=True" in stripped:
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-78 (OS Command Injection)",
                "fix": "Avoid shell=True and pass command arguments as a list."
            })

        # 5. CWE-798: Hardcoded Credentials / Secrets
        elif any(secret in stripped.lower() for secret in ["password =", "secret_key =", "api_key ="]) and not "os.environ" in stripped:
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-798 (Hardcoded Credentials)",
                "fix": "Load sensitive keys securely from environment variables (os.environ)."
            })
            
    return vulnerabilities

if __name__ == "__main__":
    files_to_check = sys.argv[1:]
    total_issues = 0
    all_reports = []

    for file in files_to_check:
        issues = audit_file(file)
        if issues:
            total_issues += len(issues)
            all_reports.append((file, issues))

    if total_issues > 0:
        print("\n" + RED + "═" * 65 + RESET)
        print(RED + BOLD + "🛡️  AGENTX SECURITY SWARM — COMMIT REJECTED" + RESET)
        print(RED + "═" * 65 + RESET)
        
        for file, issues in all_reports:
            print(f"\n{BLUE + BOLD}📁 Target File: {file}{RESET}")
            for vuln in issues:
                print(f"   {RED}[!] Line {vuln['line']} | {vuln['cwe']}{RESET}")
                print(f"       └── Vulnerable Code: {vuln['code']}")
                print(f"       {GREEN}└── Recommended Fix: {vuln['fix']}{RESET}\n")
                
        print("─" * 65)
        print(f"{RED}🛑 Security Block: Found {total_issues} vulnerability/vulnerabilities.{RESET}")
        print(f"{RED}Fix the highlighted issues above before attempting to commit again.{RESET}")
        print("═" * 65 + "\n")
        sys.exit(1)
    else:
        print(f"{GREEN}✅ AgentX Security Check Passed: Code base is secure.{RESET}")
        sys.exit(0)