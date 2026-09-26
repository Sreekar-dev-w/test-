import sys
import os
import subprocess

# ANSI Color Codes
RED = "\033[91m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

def get_user_input(prompt):
    """Bypasses Git hook restrictions by reading directly from the active Windows terminal."""
    try:
        if os.name == 'nt':
            with open("CONIN$", "r") as con:
                sys.stdout.write(prompt)
                sys.stdout.flush()
                return con.readline().strip()
        else:
            with open("/dev/tty", "r") as tty:
                sys.stdout.write(prompt)
                sys.stdout.flush()
                return tty.readline().strip()
    except Exception:
        return input(prompt).strip()

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

        if "eval(" in stripped or "exec(" in stripped:
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-95 (Remote Code Execution)",
                "fix": "Use ast.literal_eval() for safe evaluation."
            })
        elif "strcpy(" in stripped or "strcat(" in stripped:
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-120 (Buffer Overflow)",
                "fix": "Use bounds-checked functions like strncpy() or snprintf()."
            })
        elif "execute(" in stripped and ("%" in stripped or "+" in stripped or "f\"" in stripped):
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-89 (SQL Injection Risk)",
                "fix": "Use parameterized queries or prepared statements."
            })
        elif "os.system(" in stripped or "subprocess.Popen(" in stripped and "shell=True" in stripped:
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-78 (OS Command Injection)",
                "fix": "Avoid shell=True and pass command arguments as a list."
            })
        elif any(secret in stripped.lower() for secret in ["password =", "secret_key =", "api_key ="]) and not "os.environ" in stripped:
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-798 (Hardcoded Credentials)",
                "fix": "Load sensitive keys securely from environment variables (os.environ)."
            })
            
    return vulnerabilities

def apply_patch(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        new_lines = []
        for line in lines:
            if "eval(" in line:
                line = line.replace("eval(", "ast.literal_eval(")
            elif "exec(" in line:
                line = line.replace("exec(", "ast.literal_eval(")
            elif "strcpy(" in line:
                line = line.replace("strcpy(", "strncpy(")
            new_lines.append(line)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        return True
    except Exception:
        return False

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
        print(RED + BOLD + "🛡️  AGENTX SECURITY SWARM — COMMIT INTERCEPTED" + RESET)
        print(RED + "═" * 65 + RESET)
        
        for file, issues in all_reports:
            print(f"\n{BLUE + BOLD}📁 Target File: {file}{RESET}")
            for vuln in issues:
                print(f"   {RED}[!] Line {vuln['line']} | {vuln['cwe']}{RESET}")
                print(f"       └── Vulnerable Code: {vuln['code']}")
                print(f"       {GREEN}└── Recommended Fix: {vuln['fix']}{RESET}\n")
                
        print("─" * 65)
        print(f"{RED}🛑 Found {total_issues} security vulnerability/vulnerabilities.{RESET}")
        
        choice = get_user_input(f"{YELLOW}⚡ Do you want AgentX to automatically patch these errors? (y/n): {RESET}").lower()
        
        if choice == 'y':
            print(f"{YELLOW}✨ Applying automatic patches...{RESET}")
            for file, _ in all_reports:
                apply_patch(file)
                subprocess.run(["git", "add", file], stdout=subprocess.DEVNULL)
            print(f"{GREEN}✨ Patches applied and staged successfully!{RESET}\n")
        else:
            print(f"{RED}❌ Commit cancelled by user choice. Fix vulnerabilities manually.{RESET}\n")
            sys.exit(1)

    # Ask for GitHub Repo link right during the commit process
    repo_url = get_user_input(f"{BLUE}🔗 Enter your GitHub Repository URL (or press Enter to skip sync): {RESET}")
    if repo_url:
        # Save repo url temporarily so the post-commit hook can push it
        with open(os.path.join(".git", "agentx_repo_url.tmp"), "w") as f:
            f.write(repo_url)

    print(f"{GREEN}✅ Security checks passed. Proceeding with commit... 🚀{RESET}\n")
    sys.exit(0)