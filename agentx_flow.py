import os
import sys

# ANSI Color Codes
RED = "\033[91m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

def get_user_input(prompt):
    """Bypasses Git hook EOFError by reading directly from the active terminal window."""
    try:
        if os.name == 'nt':
            # Windows terminal console stream
            with open("CONIN$", "r") as con:
                sys.stdout.write(prompt)
                sys.stdout.flush()
                return con.readline().strip()
        else:
            # Unix / Mac terminal stream
            with open("/dev/tty", "r") as tty:
                sys.stdout.write(prompt)
                sys.stdout.flush()
                return tty.readline().strip()
    except Exception:
        # Fallback to standard input if terminal stream fails
        return input(prompt).strip()

def should_skip(file_path):
    ignored_dirs = ['node_modules', 'venv', '.git', '__pycache__', 'dist', 'build']
    base_name = os.path.basename(file_path)
    if base_name in ['agentx_flow.py', 'audit_cli.py']:
        return True
    parts = os.path.normpath(file_path).split(os.sep)
    return any(d in parts for d in ignored_dirs)

def audit_and_fix_file(file_path):
    if should_skip(file_path) or not os.path.exists(file_path):
        return 0
    
    if not file_path.endswith(('.py', '.js', '.c', '.cpp', '.ts')):
        return 0

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return 0

    vulnerabilities = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//'):
            continue

        if "eval(" in stripped or "exec(" in stripped:
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-95 (Remote Code Execution Risk)",
                "fix": "Use ast.literal_eval() instead of eval()"
            })
        elif "strcpy(" in stripped:
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-120 (Buffer Overflow Risk)",
                "fix": "Use bounds-checked strncpy() instead"
            })

    if vulnerabilities:
        # 📁 Blue Heading for File
        print(f"\n{BLUE + BOLD}📁 Target File: {file_path}{RESET}")
        
        for vuln in vulnerabilities:
            # ❌ Red Error details
            print(f"   {RED}[!] Line {vuln['line']} | {vuln['cwe']}{RESET}")
            print(f"       └── Vulnerable Code: {vuln['code']}")
            # 🟢 Green Solution / Fix directly below
            print(f"       {GREEN}└── Recommended Fix: {vuln['fix']}{RESET}\n")

        # Interactive prompt that works inside git commit!
        choice = get_user_input(f"{YELLOW}⚡ Do you want AgentX to automatically patch these errors? (y/n): {RESET}").lower()
        if choice == 'y':
            apply_patches(file_path, vulnerabilities, lines)
            print(f"{GREEN}✨ Successfully patched {file_path}!{RESET}\n")
            # Automatically stage the fixed file so the commit includes the patch
            os.system(f"git add \"{file_path}\"")
        else:
            print(f"{RED}🛑 Commit aborted due to unresolved vulnerabilities in {file_path}.{RESET}\n")
            sys.exit(1) # Stops the git commit!

    return len(vulnerabilities)

def apply_patches(file_path, vulnerabilities, lines):
    lines_to_fix = {v['line'] for v in vulnerabilities}
    new_lines = []
    
    for idx, line in enumerate(lines):
        current_line_num = idx + 1
        if current_line_num in lines_to_fix:
            if "eval(" in line:
                line = line.replace("eval(", "ast.literal_eval(")
            elif "exec(" in line:
                line = line.replace("exec(", "ast.literal_eval(")
            elif "strcpy(" in line:
                line = line.replace("strcpy(", "strncpy(")
        new_lines.append(line)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

def run_workspace_scan():
    print(f"\n{BLUE + BOLD}🛡️ AgentX Swarm: Scanning workspace for security vulnerabilities...{RESET}")
    
    files_checked = 0
    total_issues = 0

    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if not should_skip(os.path.join(root, d))]
        for file in files:
            file_path = os.path.join(root, file)
            if should_skip(file_path):
                continue
            files_checked += 1
            total_issues += audit_and_fix_file(file_path)

    print(f"{GREEN}🔍 Scan complete. Checked {files_checked} files.{RESET}\n")

if __name__ == "__main__":
    run_workspace_scan()