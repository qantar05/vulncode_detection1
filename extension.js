const vscode = require('vscode');
const { scanForVulnerabilities } = require('./scanner');
const VulnerabilitiesPanel = require('./panel');
const DependencyScanner = require('./dependencyScanner');

// Type definitions
/**
 * @typedef {Object} Vulnerability
 * @property {string} type
 * @property {string} message
 * @property {'Critical'|'High'|'Medium'|'Low'} severity
 * @property {number} line
 * @property {string} codeSnippet
 * @property {string} fix
 * @property {string} documentation
 * @property {string} [cve]
 * @property {string} detailedSolution
 * @property {string} context
 * @property {Object} [autoFix]
 * @property {string|RegExp} autoFix.pattern
 * @property {string} autoFix.replacement
 * @property {string} aiAnalysis
 * @property {string} attackScenario
 * @property {Array<Object>} testCases
 * @property {number|null} cvssScore
 * @property {string} poc
 */

/**
 * @typedef {Object} ScanResult
 * @property {Vulnerability[]} vulnerabilities
 * @property {number} riskScore
 */

let extensionStatusBarItem;
let diagnosticCollection;
let currentPanel;
let scanInProgress = false;

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
    const showPanelCommand = vscode.commands.registerCommand('vulnerabilityScanner.showPanel', () => showLastResults(extensionUri));
    const scanDependenciesCommand = vscode.commands.registerCommand('vulnerabilityScanner.scanDependencies', () => scanProjectDependencies(extensionUri));

    context.subscriptions.push(
        scanCommand,
        scanProjectCommand,
        fixAllCommand,
        showPanelCommand,
        scanDependenciesCommand,
        extensionStatusBarItem
    );

    // Set up event listeners
    setupEventListeners(context);
}

function setupEventListeners(context) {
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async document => {
            if (vscode.workspace.getConfiguration('vulnerabilityScanner').get('scanOnSave')) {
                await scanDocument(document);
            }
        })
    );

    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(async editor => {
            if (editor && vscode.workspace.getConfiguration('vulnerabilityScanner').get('scanOnOpen')) {
                await scanDocument(editor.document);
            }
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(async event => {
            if (event.affectsConfiguration('vulnerabilityScanner')) {
                const config = vscode.workspace.getConfiguration('vulnerabilityScanner');
                if (config.get('enableAI') && !config.get('openaiApiKey')) {
                    vscode.window.showWarningMessage('AI features require an OpenAI API key in settings');
                }
            }
        })
    );
}

function deactivate() {
    if (currentPanel) {
        currentPanel.dispose();
        currentPanel = undefined;
    }
    diagnosticCollection.dispose();
}

async function scanCurrentFile(extensionUri) {
    if (scanInProgress) {
        vscode.window.showInformationMessage('Scan is already in progress');
        return;
    }

    const editor = vscode.window.activeTextEditor;
    if (editor) {
        await scanDocument(editor.document, extensionUri);
    } else {
        vscode.window.showErrorMessage('No active editor found');
    }
}

async function scanEntireProject(extensionUri) {
    if (scanInProgress) {
        vscode.window.showInformationMessage('Scan is already in progress');
        return;
    }

    scanInProgress = true;
    extensionStatusBarItem.text = '$(sync~spin) Scanning project...';

    /** @type {Vulnerability[]} */
    let allVulnerabilities = [];
    try {
        const uris = await vscode.workspace.findFiles('**/*.{js,jsx,ts,tsx,java,py,go,rb,php}', '**/node_modules/**');

        for (const uri of uris) {
            try {
                const document = await vscode.workspace.openTextDocument(uri);
                /** @type {ScanResult} */
                const result = await scanForVulnerabilities(document);
                if (result?.vulnerabilities?.length) {
                    allVulnerabilities = allVulnerabilities.concat(result.vulnerabilities);
                }
                
                extensionStatusBarItem.text = `$(sync~spin) Scanning (${uris.indexOf(uri) + 1}/${uris.length})`;
            } catch (error) {
                console.error(`Error scanning ${uri.fsPath}:`, error);
            }
        }

        // Scan dependencies if enabled
        if (vscode.workspace.getConfiguration('vulnerabilityScanner').get('scanDependencies')) {
            const dependencyVulns = await scanProjectDependencies(extensionUri);
            allVulnerabilities = allVulnerabilities.concat(dependencyVulns);
        }

        showResults(allVulnerabilities, extensionUri);
    } catch (error) {
        vscode.window.showErrorMessage(`Project scan failed: ${error.message}`);
        console.error(error);
    } finally {
        scanInProgress = false;
        updateStatusBar(allVulnerabilities?.length || 0);
    }
}

async function scanProjectDependencies(extensionUri) {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showWarningMessage('No workspace folder found for dependency scanning');
        return [];
    }

    extensionStatusBarItem.text = '$(sync~spin) Scanning dependencies...';
    
    try {
        const workspacePath = workspaceFolders[0].uri.fsPath;
        const dependencyVulns = await DependencyScanner.scanProject(workspacePath);
        
        if (dependencyVulns.length > 0) {
            vscode.window.showInformationMessage(`Found ${dependencyVulns.length} dependency vulnerabilities`);
        }
        
        return dependencyVulns;
    } catch (error) {
        vscode.window.showErrorMessage(`Dependency scan failed: ${error.message}`);
        console.error(error);
        return [];
    }
}

/**
 * @param {vscode.TextDocument} document
 * @param {vscode.Uri} [extensionUri]
 * @returns {Promise<ScanResult>}
 */
async function scanDocument(document, extensionUri) {
    if (scanInProgress) return { vulnerabilities: [], riskScore: 0 };

    scanInProgress = true;
    extensionStatusBarItem.text = '$(sync~spin) Scanning...';
    
    try {
        /** @type {ScanResult} */
        const result = await scanForVulnerabilities(document) || { vulnerabilities: [], riskScore: 0 };
        
        // Ensure vulnerabilities is always an array
        const vulnerabilities = Array.isArray(result.vulnerabilities) 
            ? result.vulnerabilities 
            : [];
        
        updateDiagnostics(document, vulnerabilities);
        
        if (vscode.workspace.getConfiguration('vulnerabilityScanner').get('showPanelAutomatically') && vulnerabilities.length > 0) {
            showResults(vulnerabilities, extensionUri);
        }
        
        updateStatusBar(vulnerabilities.length);
        
        return {
            vulnerabilities,
            riskScore: typeof result.riskScore === 'number' ? result.riskScore : 0
        };
    } catch (error) {
        vscode.window.showErrorMessage(`Scan failed: ${error.message}`);
        console.error(error);
        return { vulnerabilities: [], riskScore: 0 };
    } finally {
        scanInProgress = false;
    }
}

function updateStatusBar(vulnerabilityCount) {
    if (vulnerabilityCount > 0) {
        extensionStatusBarItem.text = `$(warning) ${vulnerabilityCount} vulns`;
        extensionStatusBarItem.color = new vscode.ThemeColor('errorForeground');
    } else {
        extensionStatusBarItem.text = '$(shield) No issues';
        extensionStatusBarItem.color = undefined;
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
        
        const highCount = vulnerabilities.filter(v => v.severity === 'High' || v.severity === 'Critical').length;
        extensionStatusBarItem.text = `$(warning) ${vulnerabilities.length} vulns (${highCount} high)`;
        extensionStatusBarItem.color = highCount > 0 ? new vscode.ThemeColor('errorForeground') : undefined;
        
        if (vscode.workspace.getConfiguration('vulnerabilityScanner').get('showNotificationOnFind')) {
            vscode.window.showWarningMessage(
                `Found ${vulnerabilities.length} vulnerabilities (${highCount} high/critical)`,
                'Show Report'
            ).then(selection => {
                if (selection === 'Show Report') {
                    currentPanel.reveal();
                }
            });
        }
    } else {
        vscode.window.showInformationMessage('No vulnerabilities found');
        extensionStatusBarItem.text = '$(shield) No issues';
        extensionStatusBarItem.color = undefined;
    }
}

function showLastResults(extensionUri) {
    if (currentPanel) {
        currentPanel.reveal();
    } else {
        vscode.window.showInformationMessage('No previous scan results available');
    }
}

/**
 * @param {vscode.TextDocument} document
 * @param {Vulnerability[]} vulnerabilities
 */
function updateDiagnostics(document, vulnerabilities) {
    if (!document || !vulnerabilities) return;

    const diagnostics = vulnerabilities.map(vuln => {
        const line = document.lineAt(Math.max(0, vuln.line - 1));
        const diagnostic = new vscode.Diagnostic(
            line.range,
            `${vuln.type}: ${vuln.message}`,
            getDiagnosticSeverity(vuln.severity)
        );
        diagnostic.code = vuln.cve;
        diagnostic.source = 'Vulnerability Scanner';
        
        // Add related information with fix suggestion
        if (vuln.fix) {
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(document.uri, line.range),
                    `Fix: ${vuln.fix}`
                )
            ];
        }
        
        return diagnostic;
    });

    diagnosticCollection.set(document.uri, diagnostics);
}

async function fixAllVulnerabilities() {
    if (scanInProgress) {
        vscode.window.showInformationMessage('Scan is in progress, please wait');
        return;
    }

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
        { 
            placeHolder: `Found ${fixableVulns.length} auto-fixable vulnerabilities`,
            ignoreFocusOut: true
        }
    );

    if (response === 'Apply all fixes') {
        await applyFixes(editor.document, fixableVulns);
    } else if (response === 'Preview changes') {
        await showFixPreview(editor.document, fixableVulns);
    }
}

/**
 * @param {'Critical'|'High'|'Medium'|'Low'} severity
 * @returns {vscode.DiagnosticSeverity}
 */
function getDiagnosticSeverity(severity) {
    switch (severity) {
        case 'Critical': return vscode.DiagnosticSeverity.Error;
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
        // Rescan to update diagnostics
        scanDocument(document);
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

    // Apply all fixes in order
    vulnerabilities.forEach(vuln => {
        const line = diffDocument.lineAt(vuln.line - 1);
        const lineText = line.text;
        const fixedLine = lineText.replace(vuln.autoFix.pattern, vuln.autoFix.replacement);
        fixedText = fixedText.replace(lineText, fixedLine);
    });

    await vscode.commands.executeCommand(
        'vscode.diff',
        document.uri,
        {
            uri: document.uri,
            content: fixedText
        },
        'Vulnerability Fix Preview',
        { preserveFocus: true, preview: true }
    );
}

module.exports = {
    activate,
    deactivate
};