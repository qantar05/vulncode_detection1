const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const { Vulnerability } = require('./scanner');
const AttackSimulator = require('./attackSimulator');

class VulnerabilitiesPanel {
    static viewType = 'vulnerabilityScanner.panel';
    static currentPanel = undefined;
    
    // Panel properties
    panel;
    extensionUri;
    disposables = [];
    vulnerabilities = [];
    lastScanTime = null;

    constructor(panel, extensionUri, vulnerabilities) {
        this.panel = panel;
        this.extensionUri = extensionUri;
        this.vulnerabilities = vulnerabilities;
        this.lastScanTime = new Date();
        
        // Set the webview's initial html content
        this.updateWebview();

        // Listen for when the panel is disposed
        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);

        // Handle messages from the webview
        this.panel.webview.onDidReceiveMessage(
            message => this.handleWebviewMessage(message),
            null,
            this.disposables
        );
    }

    handleWebviewMessage(message) {
        switch (message.command) {
            case 'applyFix':
                this.applyAutoFix(message);
                break;
            case 'showDocumentation':
                vscode.env.openExternal(vscode.Uri.parse(message.url));
                break;
            case 'simulateAttack':
                this.simulateAttack(message);
                break;
            case 'exportReport':
                this.exportReport(message.format);
                break;
            case 'rescan':
                vscode.commands.executeCommand('vulnerabilityScanner.scan');
                break;
            case 'showTestCases':
                this.showTestCases(message.index);
                break;
        }
    }

    updateWebview() {
        this.panel.webview.html = this.getHtmlForWebview(this.vulnerabilities);
    }

    reveal() {
        this.panel.reveal();
    }

    dispose() {
        this.panel.dispose();
        while (this.disposables.length) {
            const disposable = this.disposables.pop();
            if (disposable) disposable.dispose();
        }
    }

    getHtmlForWebview(vulnerabilities) {
        // Count vulnerabilities by severity and type
        const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        const typeCounts = {};
        
        vulnerabilities.forEach(vuln => {
            severityCounts[vuln.severity]++;
            typeCounts[vuln.type] = (typeCounts[vuln.type] || 0) + 1;
        });

        // Generate chart data
        const pieChartData = {
            labels: Object.keys(severityCounts),
            datasets: [{
                data: Object.values(severityCounts),
                backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
            }],
        };

        const barChartData = {
            labels: Object.keys(typeCounts),
            datasets: [{
                label: 'Vulnerability Types',
                data: Object.values(typeCounts),
                backgroundColor: '#0275d8',
            }],
        };

        // Get paths to local resources
        const styleUri = this.getWebviewUri('media', 'styles.css');
        const scriptUri = this.getWebviewUri('media', 'main.js');
        const chartJsUri = this.getWebviewUri('media', 'chart.min.js');

        // Generate vulnerability list HTML
        const vulnerabilitiesList = vulnerabilities.map((vuln, index) => this.getVulnerabilityHtml(vuln, index)).join('');

        return `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Vulnerabilities Report</title>
                <link href="${styleUri}" rel="stylesheet">
                <script src="${chartJsUri}"></script>
                <style>
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        padding: 20px;
                        background-color: var(--vscode-editor-background);
                        color: var(--vscode-editor-foreground);
                        line-height: 1.6;
                        margin: 0;
                    }
                    h1, h2, h3, h4 {
                        color: var(--vscode-editor-foreground);
                        margin-top: 0;
                    }
                    h1 {
                        font-size: 24px;
                        margin-bottom: 15px;
                        border-bottom: 1px solid var(--vscode-editorWidget-border);
                        padding-bottom: 10px;
                    }
                    h2 {
                        font-size: 20px;
                        margin: 25px 0 15px;
                    }
                    h3 {
                        font-size: 16px;
                        margin: 15px 0 10px;
                    }
                    h4 {
                        font-size: 14px;
                        margin: 10px 0 5px;
                        border-bottom: 1px solid var(--vscode-editorWidget-border);
                        padding-bottom: 5px;
                    }
                    header {
                        margin-bottom: 25px;
                    }
                    .report-meta {
                        display: flex;
                        gap: 20px;
                        font-size: 14px;
                        color: var(--vscode-descriptionForeground);
                        margin-top: 10px;
                    }
                    .dashboard {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 20px;
                        margin-bottom: 30px;
                    }
                    .chart-container {
                        background: var(--vscode-editorWidget-background);
                        padding: 15px;
                        border-radius: 5px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        border: 1px solid var(--vscode-editorWidget-border);
                    }
                    .actions {
                        display: flex;
                        gap: 10px;
                        margin-bottom: 20px;
                    }
                    .btn {
                        background: var(--vscode-button-background);
                        color: var(--vscode-button-foreground);
                        border: none;
                        padding: 8px 15px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 14px;
                        transition: background 0.2s;
                    }
                    .btn:hover {
                        background: var(--vscode-button-hoverBackground);
                    }
                    .fix-btn {
                        background: #28a745;
                    }
                    .fix-btn:hover {
                        background: #218838;
                    }
                    .simulate-btn {
                        background: #dc3545;
                    }
                    .simulate-btn:hover {
                        background: #c82333;
                    }
                    .testcase-btn {
                        background: #17a2b8;
                    }
                    .testcase-btn:hover {
                        background: #138496;
                    }
                    .vulnerability {
                        background: var(--vscode-editorWidget-background);
                        border: 1px solid var(--vscode-editorWidget-border);
                        border-radius: 5px;
                        padding: 20px;
                        margin-bottom: 20px;
                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    }
                    .vulnerability-header {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 15px;
                    }
                    .vulnerability-meta {
                        display: flex;
                        gap: 15px;
                        align-items: center;
                        margin-bottom: 15px;
                        font-size: 14px;
                    }
                    pre, code {
                        font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                        background: var(--vscode-textCodeBlock-background);
                        padding: 12px;
                        border-radius: 4px;
                        overflow-x: auto;
                        font-size: 13px;
                        margin: 10px 0;
                        border: 1px solid var(--vscode-editorWidget-border);
                    }
                    code {
                        padding: 2px 4px;
                        font-size: 90%;
                    }
                    .info-section {
                        background: var(--vscode-input-background);
                        padding: 15px;
                        border-radius: 5px;
                        margin-bottom: 15px;
                        border: 1px solid var(--vscode-input-border);
                    }
                    .ai-analysis, .attack-scenario {
                        border-left: 4px solid #6f42c1;
                    }
                    .ai-analysis h4 {
                        color: #6f42c1;
                    }
                    .attack-scenario {
                        border-left-color: #fd7e14;
                    }
                    .attack-scenario h4 {
                        color: #fd7e14;
                    }
                    .severity-critical {
                        color: #dc3545;
                    }
                    .severity-high {
                        color: #fd7e14;
                    }
                    .severity-medium {
                        color: #ffc107;
                    }
                    .severity-low {
                        color: #28a745;
                    }
                    .icon {
                        margin-right: 8px;
                        font-size: 1.2em;
                    }
                    .language-badge {
                        display: inline-block;
                        padding: 2px 8px;
                        border-radius: 12px;
                        font-size: 12px;
                        background: #6c757d;
                        color: white;
                        margin-left: 10px;
                    }
                    .cvss-badge {
                        display: inline-block;
                        padding: 2px 8px;
                        border-radius: 12px;
                        font-size: 12px;
                        color: white;
                        font-weight: bold;
                    }
                    .cvss-critical {
                        background: #dc3545;
                    }
                    .cvss-high {
                        background: #fd7e14;
                    }
                    .cvss-medium {
                        background: #ffc107;
                        color: #212529;
                    }
                    .cvss-low {
                        background: #28a745;
                    }
                    .filters {
                        display: flex;
                        gap: 10px;
                        margin-bottom: 20px;
                        flex-wrap: wrap;
                    }
                    .filters select, .filters input {
                        padding: 8px 12px;
                        border-radius: 4px;
                        border: 1px solid var(--vscode-input-border);
                        background: var(--vscode-input-background);
                        color: var(--vscode-input-foreground);
                        font-size: 14px;
                    }
                    .filters input {
                        flex-grow: 1;
                        min-width: 200px;
                    }
                    @media (max-width: 768px) {
                        .dashboard {
                            grid-template-columns: 1fr;
                        }
                        .vulnerability-header {
                            flex-direction: column;
                            align-items: flex-start;
                            gap: 10px;
                        }
                        .actions {
                            flex-wrap: wrap;
                        }
                    }
                </style>
            </head>
            <body>
                <header>
                    <h1>Security Vulnerability Report</h1>
                    <div class="report-meta">
                        <div>Scan Time: ${this.lastScanTime.toLocaleString()}</div>
                        <div>Total Vulnerabilities: ${vulnerabilities.length}</div>
                    </div>
                </header>
                
                <div class="dashboard">
                    <div class="chart-container">
                        <h3>Severity Distribution</h3>
                        <canvas id="severityChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <h3>Vulnerability Types</h3>
                        <canvas id="typeChart"></canvas>
                    </div>
                </div>

                <div class="actions">
                    <button class="btn" onclick="rescan()">🔄 Rescan Project</button>
                    <button class="btn" onclick="exportReport('html')">📄 Export as HTML</button>
                    <button class="btn" onclick="exportReport('json')">📊 Export as JSON</button>
                </div>

                <section class="vulnerabilities">
                    <h2>Found ${vulnerabilities.length} Vulnerabilities</h2>
                    <div class="filters">
                        <select id="severityFilter" onchange="filterVulnerabilities()">
                            <option value="all">All Severities</option>
                            <option value="Critical">Critical</option>
                            <option value="High">High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                        </select>
                        <select id="typeFilter" onchange="filterVulnerabilities()">
                            <option value="all">All Types</option>
                            ${Object.keys(typeCounts).map(type => `<option value="${type}">${type}</option>`).join('')}
                        </select>
                        <input type="text" id="searchInput" placeholder="Search vulnerabilities..." oninput="filterVulnerabilities()">
                    </div>
                    
                    <div id="vulnerabilitiesList">
                        ${vulnerabilitiesList}
                    </div>
                </section>

                <script src="${scriptUri}"></script>
                <script>
                    // Render charts
                    const severityCtx = document.getElementById('severityChart');
                    const severityChart = new Chart(severityCtx, {
                        type: 'pie',
                        data: ${JSON.stringify(pieChartData)},
                        options: { 
                            responsive: true,
                            plugins: {
                                legend: { position: 'right' }
                            }
                        }
                    });

                    const typeCtx = document.getElementById('typeChart');
                    const typeChart = new Chart(typeCtx, {
                        type: 'bar',
                        data: ${JSON.stringify(barChartData)},
                        options: { 
                            responsive: true,
                            scales: {
                                y: { beginAtZero: true }
                            }
                        }
                    });

                    // Store vulnerabilities data for filtering
                    const allVulnerabilities = ${JSON.stringify(vulnerabilities)};
                </script>
            </body>
            </html>
        `;
    }

    getVulnerabilityHtml(vuln, index) {
        return `
            <div class="vulnerability" data-severity="${vuln.severity}" data-type="${vuln.type}">
                <div class="vulnerability-header">
                    <h3>
                        <span class="icon">${this.getSeverityIcon(vuln.severity)}</span>
                        <span class="severity-${vuln.severity.toLowerCase()}">${vuln.type}</span>
                        <span class="language-badge">${this.getLanguageFromType(vuln.type)}</span>
                    </h3>
                    <div class="actions">
                        ${vuln.autoFix ? `<button class="btn fix-btn" onclick="applyFix(${index})">🛠️ Auto-Fix</button>` : ''}
                        ${(vuln.severity === 'High' || vuln.severity === 'Critical') ? 
                          `<button class="btn simulate-btn" onclick="simulateAttack(${index})">🔓 Simulate Attack</button>` : ''}
                        <button class="btn testcase-btn" onclick="showTestCases(${index})">🧪 Test Cases</button>
                    </div>
                </div>
                
                <div class="vulnerability-meta">
                    <span><strong>Location:</strong> Line ${vuln.line}</span>
                    ${vuln.cvssScore ? `<span class="cvss-badge cvss-${this.getCvssSeverity(vuln.cvssScore)}">CVSS: ${vuln.cvssScore.toFixed(1)}</span>` : ''}
                </div>
                
                <pre><code>${vuln.codeSnippet}</code></pre>
                
                <div class="info-section">
                    <h4>Description</h4>
                    <p>${vuln.message}</p>
                    <p>${vuln.context}</p>
                </div>
                
                ${vuln.cve ? `
                <div class="info-section">
                    <h4>CVE Information</h4>
                    <p><a href="https://nvd.nist.gov/vuln/detail/${vuln.cve}" target="_blank" onclick="showDocumentation('https://nvd.nist.gov/vuln/detail/${vuln.cve}')">${vuln.cve}</a></p>
                </div>` : ''}
                
                <div class="info-section">
                    <h4>Remediation</h4>
                    ${vuln.fix ? `<p><strong>Quick Fix:</strong> ${vuln.fix}</p>` : ''}
                    ${vuln.detailedSolution ? `<pre>${vuln.detailedSolution}</pre>` : ''}
                </div>
                
                ${vuln.aiAnalysis ? `
                <div class="info-section ai-analysis">
                    <h4>AI Analysis</h4>
                    <div class="ai-content">${vuln.aiAnalysis}</div>
                </div>` : ''}
                
                ${vuln.attackScenario ? `
                <div class="info-section attack-scenario">
                    <h4>Attack Scenario</h4>
                    <div class="scenario-content">${vuln.attackScenario}</div>
                </div>` : ''}
                
                ${vuln.documentation ? `
                <div class="info-section">
                    <h4>Learn More</h4>
                    <p><a href="${vuln.documentation}" target="_blank" onclick="showDocumentation('${vuln.documentation}')">${vuln.documentation}</a></p>
                </div>` : ''}
            </div>
        `;
    }

    getWebviewUri(...pathParts) {
        const uri = vscode.Uri.file(path.join(this.extensionUri.fsPath, ...pathParts));
        return this.panel.webview.asWebviewUri(uri).toString();
    }

    getSeverityIcon(severity) {
        switch (severity) {
            case 'Critical': return '💀';
            case 'High': return '🔥';
            case 'Medium': return '⚠️';
            case 'Low': return 'ℹ️';
            default: return '⚪';
        }
    }

    getLanguageFromType(type) {
        const languageMap = {
            'SQL Injection': 'SQL',
            'XSS': 'JS/HTML',
            'Prototype Pollution': 'JS',
            'Command Injection': 'System',
            'Insecure Deserialization': 'Data',
            'XXE Injection': 'XML',
            'Path Traversal': 'FS',
            'Hardcoded Secret': 'Secret'
        };
        return languageMap[type] || 'Code';
    }

    getCvssSeverity(score) {
        if (score >= 9) return 'critical';
        if (score >= 7) return 'high';
        if (score >= 4) return 'medium';
        return 'low';
    }

    async applyAutoFix(message) {
        const editor = vscode.window.activeTextEditor;
        if (!editor || !Array.isArray(this.vulnerabilities) || typeof message.index !== 'number') return;

        const vuln = this.vulnerabilities[message.index];
        if (!vuln?.autoFix) return;

        try {
            await editor.edit(editBuilder => {
                const line = editor.document.lineAt(vuln.line - 1);
                const fixedCode = line.text.replace(vuln.autoFix.pattern, vuln.autoFix.replacement);
                editBuilder.replace(line.range, fixedCode);
            });
            vscode.window.showInformationMessage(`Fixed ${vuln.type} vulnerability`);
            
            // Update the panel to show the vulnerability is fixed
            this.vulnerabilities = this.vulnerabilities.filter((_, i) => i !== message.index);
            this.updateWebview();
        } catch (error) {
            vscode.window.showErrorMessage(`Fix failed: ${error.message}`);
        }
    }

    async simulateAttack(message) {
        if (!Array.isArray(this.vulnerabilities) || typeof message.index !== 'number') return;

        const vuln = this.vulnerabilities[message.index];
        if (!vuln) return;

        try {
            await AttackSimulator.simulateAttack(vuln);
        } catch (error) {
            vscode.window.showErrorMessage(`Attack simulation failed: ${error.message}`);
        }
    }

    async showTestCases(index) {
        if (!Array.isArray(this.vulnerabilities)) return;

        const vuln = this.vulnerabilities[index];
        if (!vuln?.testCases?.length) {
            vscode.window.showInformationMessage('No test cases available for this vulnerability');
            return;
        }

        const testCasesContent = vuln.testCases.map((testCase, i) => `
            <h3>${testCase.name || `Test Case ${i + 1}`}</h3>
            <p><strong>Input:</strong> <code>${testCase.input}</code></p>
            <p><strong>Vulnerable Behavior:</strong> ${testCase.vulnerableBehavior}</p>
            <p><strong>Fixed Behavior:</strong> ${testCase.fixedBehavior}</p>
            <hr>
        `).join('');

        const panel = vscode.window.createWebviewPanel(
            'testCases',
            `Test Cases for ${vuln.type}`,
            vscode.ViewColumn.Beside,
            { enableScripts: true }
        );

        panel.webview.html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial; padding: 20px; }
                    h2 { color: #333; }
                    h3 { color: #555; }
                    code { background: #f5f5f5; padding: 2px 4px; }
                    hr { border: 0; border-top: 1px solid #eee; margin: 20px 0; }
                </style>
            </head>
            <body>
                <h2>Test Cases for ${vuln.type}</h2>
                <p><strong>Location:</strong> Line ${vuln.line}</p>
                ${testCasesContent}
            </body>
            </html>
        `;
    }

    async exportReport(format) {
        const options = {
            defaultUri: vscode.Uri.file(`vulnerability-report-${new Date().toISOString().split('T')[0]}.${format}`),
            filters: {
                [format.toUpperCase()]: [format],
                'All Files': ['*']
            }
        };

        try {
            const uri = await vscode.window.showSaveDialog(options);
            if (!uri) return;

            let content;
            if (format === 'html') {
                content = this.getHtmlForWebview(this.vulnerabilities);
            } else if (format === 'json') {
                content = JSON.stringify({
                    metadata: {
                        generatedAt: new Date().toISOString(),
                        tool: "Vulnerability Scanner",
                        version: "1.0"
                    },
                    vulnerabilities: this.vulnerabilities
                }, null, 2);
            }

            await fs.promises.writeFile(uri.fsPath, content);
            vscode.window.showInformationMessage(`Report exported successfully to ${uri.fsPath}`);
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to export report: ${error.message}`);
        }
    }

    static createOrShow(extensionUri, vulnerabilities) {
        const column = vscode.window.activeTextEditor?.viewColumn || vscode.ViewColumn.One;
        
        // If we already have a panel, show it
        if (VulnerabilitiesPanel.currentPanel) {
            VulnerabilitiesPanel.currentPanel.panel.reveal(column);
            VulnerabilitiesPanel.currentPanel.vulnerabilities = vulnerabilities;
            VulnerabilitiesPanel.currentPanel.lastScanTime = new Date();
            VulnerabilitiesPanel.currentPanel.updateWebview();
            return VulnerabilitiesPanel.currentPanel;
        }

        // Otherwise, create a new panel
        const panel = vscode.window.createWebviewPanel(
            VulnerabilitiesPanel.viewType,
            'Vulnerabilities Report',
            column,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [extensionUri],
                enableCommandUris: true
            }
        );

        VulnerabilitiesPanel.currentPanel = new VulnerabilitiesPanel(panel, extensionUri, vulnerabilities);
        return VulnerabilitiesPanel.currentPanel;
    }
}

module.exports = VulnerabilitiesPanel;