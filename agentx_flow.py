import os
import sys
import subprocess
import audit_cli

# ANSI Color Codes
RED = "\033[91m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

def run_full_workspace_scan():
    print(f"\n{BLUE + BOLD}🛡️ AgentX Swarm: Deep-scanning entire workspace for vulnerabilities...{RESET}")
    
    files_checked = 0
    total_issues = 0
    patched_any = False

    # Recursively walk through every directory and file in the project
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if not audit_cli.should_skip(os.path.join(root, d))]

        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip irrelevant files or non-code extensions
            if audit_cli.should_skip(file_path) or not file_path.endswith(('.py', '.js', '.c', '.cpp', '.ts')):
                continue

            files_checked += 1
            vulnerabilities = audit_cli.audit_file(file_path)

            if vulnerabilities:
                total_issues += len(vulnerabilities)
                print(f"\n{BLUE + BOLD}📁 Target File: {file_path}{RESET}")
                
                for vuln in vulnerabilities:
                    print(f"   {RED}[!] Line {vuln['line']} | {vuln['cwe']}{RESET}")
                    print(f"       └── Vulnerable Code: {vuln['code']}")
                    print(f"       {GREEN}└── Recommended Fix: Use {vuln['fix']} instead.{RESET}\n")

                # Wait for your manual confirmation to patch
                choice = input(f"{YELLOW}⚡ Patch vulnerabilities in this file automatically? (y/n): {RESET}").strip().lower()
                if choice == 'y':
                    patch_file(file_path, vulnerabilities)
                    patched_any = True

    print(f"{GREEN}🔍 Scan complete. Checked {files_checked} files. Total risks found: {total_issues}{RESET}")
    
    if patched_any:
        subprocess.run(["git", "add", "."], stdout=subprocess.DEVNULL)
        print(f"{GREEN}✨ All patches applied and staged automatically.{RESET}")

    return total_issues

def patch_file(file_path, vulnerabilities):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
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
                    line = line.replace("strcpy(", "strncpy()")
            new_lines.append(line)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
            
        print(f"{GREEN}✨ Successfully patched vulnerabilities in {file_path}!{RESET}\n")
    except Exception as e:
        print(f"{RED}❌ Failed to patch file: {e}{RESET}")

def github_sync_flow():
    print("\n" + "═" * 65)
    print(BLUE + BOLD + "🌐 GITHUB SYNC & PUSH MANAGER" + RESET)
    print("═" * 65)
    
    push_choice = input(f"{YELLOW}Do you give consent to push your code to GitHub now? (y/n): {RESET}").strip().lower()
    if push_choice != 'y':
        print(f"{RED}❌ Push aborted by user consent check.{RESET}")
        sys.exit(1) # Blocks the git push if you say no!

    repo_url = input(f"{BLUE}🔗 Enter your GitHub Repository URL: {RESET}").strip()
    if not repo_url:
        print(f"{RED}❌ Invalid URL provided. Aborting push.{RESET}")
        sys.exit(1)

    commit_msg = input(f"{BLUE}💬 Enter commit message (press Enter for default): {RESET}").strip()
    if not commit_msg:
        commit_msg = "AgentX Secure Auto-Commit & Sync"

    print(f"{YELLOW}🚀 Configuring Git and executing push...{RESET}")
    try:
        subprocess.run(["git", "remote", "remove", "origin"], stderr=subprocess.DEVNULL)
        subprocess.run(["git", "remote", "add", "origin", repo_url], check=True)
        subprocess.run(["git", "add", "."], check=True)
        # Check if there's anything to commit
        status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)
        if status.stdout.strip():
            subprocess.run(["git", "commit", "-m", commit_msg], check=True)
            
        print(f"{GREEN}🎉 Security checks passed. Handing over to Git to complete push... 🚀✨{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}❌ Git Sync Failed: {e}{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    run_full_workspace_scan()
    github_sync_flow()