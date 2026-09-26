const vscode = require('vscode');
const http = require('http');

let diagnosticCollection;
let debounceTimer = null;

function activate(context) {
    console.log('🚀 AgentX Background Linter is active and running!');

    diagnosticCollection = vscode.languages.createDiagnosticCollection('agentx-security');
    context.subscriptions.push(diagnosticCollection);

    // Trigger on active editor change immediately
    if (vscode.window.activeTextEditor) {
        triggerBackgroundAudit(vscode.window.activeTextEditor.document);
    }

    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(event => {
            const editor = vscode.window.activeTextEditor;
            if (editor && event.document === editor.document) {
                triggerBackgroundAudit(editor.document);
            }
        })
    );

    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor) {
                triggerBackgroundAudit(editor.document);
            }
        })
    );
}

function triggerBackgroundAudit(document) {
    if (document.uri.scheme !== 'file') return;
    
    const code = document.getText();
    if (!code.trim()) return;

    if (debounceTimer) clearTimeout(debounceTimer);

    debounceTimer = setTimeout(() => {
        sendCodeToBackend(document, code);
    }, 800); // Faster trigger (0.8s)
}

function sendCodeToBackend(document, codeText) {
    const data = JSON.stringify({ code: codeText });

    const reqOptions = {
        hostname: '127.0.0.1',
        port: 8000,
        path: '/vscode-analyze',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data)
        }
    };

    const req = http.request(reqOptions, (res) => {
        let responseBody = '';
        res.on('data', (chunk) => { responseBody += chunk; });
        res.on('end', () => {
            try {
                const jsonRes = JSON.parse(responseBody);
                console.log("AgentX Server Response Received:", jsonRes);
                updateEditorDiagnostics(document, jsonRes.vulnerabilities || []);
            } catch (e) {
                console.error("AgentX Parse Error:", e);
            }
        });
    });

    req.on('error', (error) => {
        console.log("❌ AgentX Connection Error to Flask:", error.message);
    });

    req.write(data);
    req.end();
}

function updateEditorDiagnostics(document, vulnerabilities) {
    const diagnostics = [];

    vulnerabilities.forEach(vuln => {
        const line = Math.max(0, (vuln.line || 1) - 1);
        if (line >= document.lineCount) return;
        
        const lineObj = document.lineAt(line);
        const range = new vscode.Range(
            new vscode.Position(line, 0),
            new vscode.Position(line, lineObj.text.length)
        );

        const diagnostic = new vscode.Diagnostic(
            range,
            `🛡️ AgentX Security: ${vuln.message}`,
            vscode.DiagnosticSeverity.Error
        );
        diagnostic.source = 'AgentX Swarm';
        diagnostics.push(diagnostic);
    });

    diagnosticCollection.set(document.uri, diagnostics);
}

function deactivate() {
    if (diagnosticCollection) diagnosticCollection.clear();
}

module.exports = { activate, deactivate };