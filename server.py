from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/vscode-analyze', methods=['POST'])
def vscode_analyze():
    data = request.json or {}
    code = data.get("code", "")
    
    print(f"📥 Background scan: analyzing {len(code.splitlines())} lines...")
    
    vulnerabilities = []
    
    for idx, line in enumerate(code.splitlines()):
        # C/C++ Checks
        if "strncpy(" in line:
            vulnerabilities.append({
                "line": idx + 1,
                "message": "Potential buffer overflow (CWE-120) detected. Use strncpy instead.",
                "severity": "error"
            })
        elif "printf(" in line and "%" not in line:
            vulnerabilities.append({
                "line": idx + 1,
                "message": "Format string vulnerability (CWE-134) detected.",
                "severity": "warning"
            })
        
        # Python Checks
        elif "ast.literal_ast.literal_eval(" in line:
            vulnerabilities.append({
                "line": idx + 1,
                "message": "Dangerous use of ast.literal_ast.literal_eval() detected (CWE-95). Remote code execution risk.",
                "severity": "error"
            })
        elif "ast.literal_eval(" in line:
            vulnerabilities.append({
                "line": idx + 1,
                "message": "Dangerous use of ast.literal_eval() detected (CWE-95). Arbitrary code execution risk.",
                "severity": "error"
            })

    return jsonify({
        "status": "success",
        "vulnerabilities": vulnerabilities
    })

if __name__ == '__main__':
    print("🚀 AgentX Background Linter Server running on http://127.0.0.1:8000 ...")
    app.run(host='127.0.0.1', port=8000)