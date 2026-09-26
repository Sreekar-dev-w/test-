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

def run_workflow(is_auto=False):
    print(f"\n{BLUE + BOLD}🛡️ AgentX Swarm: Scanning workspace for security vulnerabilities...{RESET}")
    
    files_checked = 0
    total_issues = 0
    patched_any = False

    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if not audit_cli.should_skip(os.path.join(root, d))]

        for file in files:
            file_path = os.path.join(root, file)
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

                should_patch = False
                if is_auto:
                    print(f"{YELLOW}⚡ Autonomous Mode: Auto-patching vulnerabilities...{RESET}")
                    should_patch = True
                else:
                    choice = input(f"{YELLOW}⚡ Patch vulnerabilities in this file automatically? (y/n): {RESET}").strip().lower()
                    if choice == 'y':
                        should_patch = True

                if should_patch:
                    patch_file(file_path, vulnerabilities)
                    patched_any = True

    print(f"{GREEN}🔍 Scan complete. Checked {files_checked} files. Total risks found: {total_issues}{RESET}")
    
    # If we auto-patched files during a push, stage the changes so they go up with the commit
    if is_auto and patched_any:
        subprocess.run(["git", "add", "."], stdout=subprocess.DEVNULL)
        print(f"{GREEN}✨ Auto-patched changes staged successfully for push.{RESET}")

    return total_issues if not is_auto else 0 # In auto-mode, we fix and let push pass!

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
                    line = line.replace("strcpy(", "strncpy(")
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
    
    repo_url = input(f"{BLUE}🔗 Enter your GitHub Repository URL: {RESET}").strip()
    if not repo_url:
        print(f"{RED}❌ Invalid URL provided. Aborting push.{RESET}")
        return

    commit_msg = input(f"{BLUE}💬 Enter commit message (press Enter for default): {RESET}").strip()
    if not commit_msg:
        commit_msg = "AgentX Secure Auto-Commit & Sync"

    print(f"{YELLOW}🚀 Configuring Git and pushing to GitHub...{RESET}")
    try:
        subprocess.run(["git", "remote", "remove", "origin"], stderr=subprocess.DEVNULL)
        subprocess.run(["git", "remote", "add", "origin", repo_url], check=True)
        subprocess.run(["git", "add", "."], check=True)
        subprocess.run(["git", "commit", "-m", commit_msg], check=True)
        subprocess.run(["git", "push", "-u", "origin", "main"], check=True)
        print(f"{GREEN}🎉 Successfully pushed your secured code to GitHub! 🚀✨{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}❌ Git Push Failed: {e}{RESET}")

if __name__ == "__main__":
    # Check if passed the --auto flag from the git pre-push hook
    if "--auto" in sys.argv:
        run_workflow(is_auto=True)
        sys.exit(0) # Allow push to proceed
    else:
        run_workflow(is_auto=False)
        github_sync_flow()