import os

def should_skip(file_path):
    ignored_dirs = ['node_modules', 'venv', '.git', '__pycache__', 'dist', 'build']
    if os.path.basename(file_path) in ['audit_cli.py', 'agentx_flow.py']:
        return True
    parts = os.path.normpath(file_path).split(os.sep)
    return any(d in parts for d in ignored_dirs)

def audit_file(file_path):
    """Scans a file and returns a list of discovered vulnerabilities."""
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
                "fix": "ast.literal_eval("
            })
        elif "strcpy(" in stripped:
            vulnerabilities.append({
                "line": idx + 1,
                "code": stripped,
                "cwe": "CWE-120 (Buffer Overflow)",
                "fix": "strncpy("
            })
            
    return vulnerabilities