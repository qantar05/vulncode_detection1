const vscode = require('vscode');
const { scanForVulnerabilities } = require('./scanner');
const VulnerabilitiesPanel = require('./panel');

// Type definitions
/**
 * @typedef {Object} Vulnerability
 * @property {string} type
 * @property {string} message
 * @property {'High'|'Medium'|'Low'} severity
 * @property {number} line
 * @property {string} [cve]
 * @property {Object} [autoFix]
 * @property {string|RegExp} autoFix.pattern
 * @property {string} autoFix.replacement
 */

/**
 * @typedef {Object} ScanResult
 * @property {Vulnerability[]} vulnerabilities
 * @property {number} [riskScore]
 */

let extensionStatusBarItem;
let diagnosticCollection;
let currentPanel;

async function activate(context) {
    console.log('Extension "vulnerability-scanner" is now active!');

    // Store the extension context
    const extensionUri = context.extensionUri;

    // Create status bar item
    extensionStatusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    extensionStatusBarItem.text = '$(shield) Scan';
    extensionStatusBarItem.tooltip = 'Scan for vulnerabilities';
    extensionStatusBarItem.command = 'vulnerabilityScanner.scan';
    extensionStatusBarItem.show();

    // Initialize diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection('vulnerabilities');
    context.subscriptions.push(diagnosticCollection);

    // Register commands with proper context
    const scanCommand = vscode.commands.registerCommand('vulnerabilityScanner.scan', () => scanCurrentFile(extensionUri));
    const scanProjectCommand = vscode.commands.registerCommand('vulnerabilityScanner.scanProject', () => scanEntireProject(extensionUri));
    const fixAllCommand = vscode.commands.registerCommand('vulnerabilityScanner.fixAll', fixAllVulnerabilities);

    context.subscriptions.push(
        scanCommand,
        scanProjectCommand,
        fixAllCommand,
        extensionStatusBarItem
    );

    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(document => {
            if (vscode.workspace.getConfiguration('vulnerabilityScanner').get('scanOnSave')) {
                scanDocument(document);
            }
        })
    );

    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && vscode.workspace.getConfiguration('vulnerabilityScanner').get('scanOnOpen')) {
                scanDocument(editor.document);
            }
        })
    );
}

function deactivate() {
    if (currentPanel) {
        currentPanel.dispose();
        currentPanel = undefined;
    }
}

async function scanCurrentFile(extensionUri) {
    const editor = vscode.window.activeTextEditor;
    if (editor) {
        await scanDocument(editor.document, extensionUri);
    } else {
        vscode.window.showErrorMessage('No active editor found');
    }
}

async function scanEntireProject(extensionUri) {
    const uris = await vscode.workspace.findFiles('**/*.{js,jsx,ts,tsx,java,py}', '**/node_modules/**');
    /** @type {Vulnerability[]} */
    let allVulnerabilities = [];

    extensionStatusBarItem.text = '$(sync~spin) Scanning...';
    
    for (const uri of uris) {
        try {
            const document = await vscode.workspace.openTextDocument(uri);
            /** @type {ScanResult} */
            const result = await scanForVulnerabilities(document);
            if (result && result.vulnerabilities) {
                allVulnerabilities = allVulnerabilities.concat(result.vulnerabilities);
            }
            
            extensionStatusBarItem.text = `$(sync~spin) Scanning (${uris.indexOf(uri) + 1}/${uris.length})`;
        } catch (error) {
            console.error(`Error scanning ${uri.fsPath}:`, error);
        }
    }

    extensionStatusBarItem.text = '$(shield) Scan';
    showResults(allVulnerabilities, extensionUri);
}

/**
 * @param {vscode.TextDocument} document
 * @param {vscode.Uri} [extensionUri]
 * @returns {Promise<ScanResult>}
 */
async function scanDocument(document, extensionUri) {
    try {
        /** @type {ScanResult} */
        const result = await scanForVulnerabilities(document) || { vulnerabilities: [] };
        
        // Ensure vulnerabilities is always an array
        const vulnerabilities = Array.isArray(result.vulnerabilities) 
            ? result.vulnerabilities 
            : [];
        
        updateDiagnostics(document, vulnerabilities);
        
        if (vscode.workspace.getConfiguration('vulnerabilityScanner').get('showPanelAutomatically')) {
            showResults(vulnerabilities, extensionUri);
        }
        
        return {
            vulnerabilities,
            riskScore: typeof result.riskScore === 'number' ? result.riskScore : 0
        };
    } catch (error) {
        vscode.window.showErrorMessage(`Scan failed: ${error.message}`);
        console.error(error);
        return { vulnerabilities: [], riskScore: 0 };
    }
}

/**
 * @param {Vulnerability[]} vulnerabilities
 * @param {vscode.Uri} extensionUri
 */
function showResults(vulnerabilities, extensionUri) {
    if (!extensionUri) {
        vscode.window.showErrorMessage('Extension resources not available');
        return;
    }

    if (vulnerabilities.length > 0) {
        currentPanel = VulnerabilitiesPanel.createOrShow(
            extensionUri,
            vulnerabilities
        );
        
        const highCount = vulnerabilities.filter(v => v.severity === 'High').length;
        extensionStatusBarItem.text = `$(warning) ${vulnerabilities.length} vulns (${highCount} high)`;
        extensionStatusBarItem.color = highCount > 0 ? new vscode.ThemeColor('errorForeground') : undefined;
    } else {
        vscode.window.showInformationMessage('No vulnerabilities found');
        extensionStatusBarItem.text = '$(shield) No issues';
        extensionStatusBarItem.color = undefined;
    }
}

/**
 * @param {vscode.TextDocument} document
 * @param {Vulnerability[]} vulnerabilities
 */
function updateDiagnostics(document, vulnerabilities) {
    if (!document || !vulnerabilities) return;

    const diagnostics = vulnerabilities.map(vuln => {
        const line = document.lineAt(vuln.line - 1);
        const diagnostic = new vscode.Diagnostic(
            line.range,
            `${vuln.type}: ${vuln.message}`,
            getDiagnosticSeverity(vuln.severity)
        );
        diagnostic.code = vuln.cve;
        diagnostic.source = 'Vulnerability Scanner';
        return diagnostic;
    });

    diagnosticCollection.set(document.uri, diagnostics);
}

async function fixAllVulnerabilities() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const result = await scanDocument(editor.document);
    /** @type {Vulnerability[]} */
    const fixableVulns = result.vulnerabilities.filter(v => v.autoFix);

    if (fixableVulns.length === 0) {
        vscode.window.showInformationMessage('No auto-fixable vulnerabilities found');
        return;
    }

    const response = await vscode.window.showQuickPick(
        ['Preview changes', 'Apply all fixes', 'Cancel'],
        { placeHolder: `Found ${fixableVulns.length} auto-fixable vulnerabilities` }
    );

    if (response === 'Apply all fixes') {
        await applyFixes(editor.document, fixableVulns);
    } else if (response === 'Preview changes') {
        await showFixPreview(editor.document, fixableVulns);
    }
}

/**
 * @param {'High'|'Medium'|'Low'} severity
 * @returns {vscode.DiagnosticSeverity}
 */
function getDiagnosticSeverity(severity) {
    switch (severity) {
        case 'High': return vscode.DiagnosticSeverity.Error;
        case 'Medium': return vscode.DiagnosticSeverity.Warning;
        case 'Low': return vscode.DiagnosticSeverity.Information;
        default: return vscode.DiagnosticSeverity.Hint;
    }
}

/**
 * @param {vscode.TextDocument} document
 * @param {Vulnerability[]} vulnerabilities
 */
async function applyFixes(document, vulnerabilities) {
    const edit = new vscode.WorkspaceEdit();
    
    vulnerabilities.forEach(vuln => {
        const line = document.lineAt(vuln.line - 1);
        const fixedText = line.text.replace(vuln.autoFix.pattern, vuln.autoFix.replacement);
        edit.replace(document.uri, line.range, fixedText);
    });

    const applied = await vscode.workspace.applyEdit(edit);
    if (applied) {
        vscode.window.showInformationMessage(`Fixed ${vulnerabilities.length} vulnerabilities`);
    } else {
        vscode.window.showErrorMessage('Failed to apply fixes');
    }
}

/**
 * @param {vscode.TextDocument} document
 * @param {Vulnerability[]} vulnerabilities
 */
async function showFixPreview(document, vulnerabilities) {
    const diffDocument = await vscode.workspace.openTextDocument(document.uri);
    const originalText = diffDocument.getText();
    let fixedText = originalText;

    vulnerabilities.forEach(vuln => {
        const lineStart = diffDocument.lineAt(vuln.line - 1).range.start;
        const lineEnd = diffDocument.lineAt(vuln.line - 1).range.end;
        const lineRange = new vscode.Range(lineStart, lineEnd);
        const lineText = diffDocument.getText(lineRange);
        fixedText = fixedText.replace(lineText, lineText.replace(vuln.autoFix.pattern, vuln.autoFix.replacement));
    });

    await vscode.commands.executeCommand(
        'vscode.diff',
        document.uri,
        {
            uri: document.uri,
            content: fixedText
        },
        'Vulnerability Fix Preview'
    );
}

module.exports = {
    activate,
    deactivate
};