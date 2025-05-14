const vscode = require('vscode');
const { Vulnerability } = require('./scanner');

class VulnerabilitiesPanel {
    static viewType = 'vulnerabilityScanner.panel';
    
    // Declare properties at class level
    panel;
    extensionUri;
    disposables = [];
    vulnerabilities = [];

    constructor(panel, extensionUri, vulnerabilities) {
        this.panel = panel;
        this.extensionUri = extensionUri;
        this.vulnerabilities = vulnerabilities;
        this.panel.webview.html = this.getHtmlForWebview(vulnerabilities);
        
        // Handle messages from the webview
        this.panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'applyFix':
                        this.applyAutoFix(message);
                        break;
                    case 'showDocumentation':
                        vscode.env.openExternal(vscode.Uri.parse(message.url));
                        break;
                }
            },
            null,
            this.disposables
        );
    }

    getHtmlForWebview(vulnerabilities) {
        // Count vulnerabilities by severity and type
        const severityCounts = { High: 0, Medium: 0, Low: 0 };
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
                backgroundColor: ['#dc3545', '#ffc107', '#28a745'],
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

        const style = `
            <style>
                body {
                    font-family: Arial, sans-serif;
                    padding: 20px;
                    background-color: #f9f9f9;
                    color: #333;
                }
                h1 {
                    color: #2c3e50;
                    margin-bottom: 20px;
                    border-bottom: 1px solid #eee;
                    padding-bottom: 10px;
                }
                .dashboard {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                    margin-bottom: 30px;
                }
                .chart-container {
                    background: white;
                    padding: 15px;
                    border-radius: 5px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .chart-container h3 {
                    margin-top: 0;
                    text-align: center;
                }
                .vulnerability {
                    background: #fff;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 15px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                .vulnerability-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .vulnerability h3 {
                    margin-top: 0;
                    color: #d9534f;
                    display: flex;
                    align-items: center;
                }
                .vulnerability h3 .icon {
                    margin-right: 10px;
                    font-size: 1.2em;
                }
                .vulnerability pre {
                    background: #f5f5f5;
                    padding: 10px;
                    border-radius: 3px;
                    overflow-x: auto;
                    font-family: Consolas, monospace;
                }
                .vulnerability a {
                    color: #0275d8;
                    text-decoration: none;
                }
                .vulnerability a:hover {
                    text-decoration: underline;
                }
                .severity-high { color: #dc3545; }
                .severity-medium { color: #ffc107; }
                .severity-low { color: #28a745; }
                .info-section {
                    background: #e9ecef;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 10px;
                }
                .info-section h4 {
                    margin-top: 0;
                    border-bottom: 1px solid #ccc;
                    padding-bottom: 5px;
                }
                .fix-btn {
                    background: #5cb85c;
                    color: white;
                    border: none;
                    padding: 5px 10px;
                    border-radius: 3px;
                    cursor: pointer;
                    margin-left: 10px;
                }
                .fix-btn:hover {
                    background: #4cae4c;
                }
                .language-badge {
                    display: inline-block;
                    padding: 2px 5px;
                    border-radius: 3px;
                    font-size: 0.8em;
                    background: #6c757d;
                    color: white;
                    margin-left: 10px;
                }
            </style>
        `;

        // Generate vulnerability list with all new fields
        const vulnerabilitiesList = vulnerabilities.map((vuln, index) => `
            <div class="vulnerability">
                <div class="vulnerability-header">
                    <h3>
                        <span class="icon">${this.getSeverityIcon(vuln.severity)}</span>
                        <span class="severity-${vuln.severity.toLowerCase()}">${vuln.type}</span>
                        <span class="language-badge">${this.getLanguageFromType(vuln.type)}</span>
                    </h3>
                    ${vuln.autoFix ? `<button class="fix-btn" onclick="applyFix(${index})">🛠️ Auto-Fix</button>` : ''}
                </div>
                <p><strong>Location:</strong> Line ${vuln.line}</p>
                <pre>${vuln.codeSnippet}</pre>
                
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
                
                ${vuln.documentation ? `
                <div class="info-section">
                    <h4>Learn More</h4>
                    <p><a href="${vuln.documentation}" target="_blank" onclick="showDocumentation('${vuln.documentation}')">${vuln.documentation}</a></p>
                </div>` : ''}
                
                ${vuln.aiAnalysis ? `
                <div class="info-section">
                    <h4>AI Analysis</h4>
                    <p>${vuln.aiAnalysis}</p>
                </div>` : ''}
            </div>
        `).join('');

        return `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Vulnerabilities Report</title>
                ${style}
                <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            </head>
            <body>
                <h1>Security Vulnerability Report</h1>
                
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

                <h2>Found ${vulnerabilities.length} Vulnerabilities</h2>
                ${vulnerabilitiesList}

                <script>
                    // Render charts
                    const severityCtx = document.getElementById('severityChart');
                    const severityChart = new Chart(severityCtx, {
                        type: 'pie',
                        data: ${JSON.stringify(pieChartData)},
                        options: { responsive: true }
                    });

                    const typeCtx = document.getElementById('typeChart');
                    const typeChart = new Chart(typeCtx, {
                        type: 'bar',
                        data: ${JSON.stringify(barChartData)},
                        options: { responsive: true }
                    });

                    // Handle messages to VS Code
                    function applyFix(index) {
                        const vscode = acquireVsCodeApi();
                        vscode.postMessage({
                            command: 'applyFix',
                            index: index
                        });
                    }

                    function showDocumentation(url) {
                        const vscode = acquireVsCodeApi();
                        vscode.postMessage({
                            command: 'showDocumentation',
                            url: url
                        });
                    }
                </script>
            </body>
            </html>
        `;
    }

    // Helper to get language from vulnerability type
    getLanguageFromType(type) {
        const languageMap = {
            'SQL Injection': 'SQL',
            'XSS': 'JS/HTML',
            'Prototype Pollution': 'JS',
            'Command Injection': 'System',
            'Insecure Deserialization': 'Data'
        };
        return languageMap[type] || 'Code';
    }

    getSeverityIcon(severity) {
        switch (severity) {
            case 'High': return '🔴';
            case 'Medium': return '🟡';
            case 'Low': return '🟢';
            default: return '⚪';
        }
    }

    // Handle auto-fix requests
    async applyAutoFix(message) {
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;
    
        // Add proper type checking
        if (!Array.isArray(this.vulnerabilities)) return;
        if (typeof message.index !== 'number') return;
    
        const vuln = this.vulnerabilities[message.index];
        if (!vuln?.autoFix) return;
    
        try {
            await editor.edit(editBuilder => {
                const line = editor.document.lineAt(vuln.line - 1);
                const fixedCode = line.text.replace(vuln.autoFix.pattern, vuln.autoFix.replacement);
                editBuilder.replace(line.range, fixedCode);
            });
            vscode.window.showInformationMessage(`Fixed ${vuln.type} vulnerability`);
        } catch (error) {
            vscode.window.showErrorMessage(`Fix failed: ${error.message}`);
        }
    }

    static createOrShow(extensionUri, vulnerabilities) {
    if (!extensionUri) {
        vscode.window.showErrorMessage('Extension resources not available');
        return;
    }

    const column = vscode.window.activeTextEditor?.viewColumn || vscode.ViewColumn.One;
    const panel = vscode.window.createWebviewPanel(
        VulnerabilitiesPanel.viewType,
        'Vulnerabilities Report',
        column,
        {
            enableScripts: true,
            retainContextWhenHidden: true,
            localResourceRoots: [extensionUri]
        }
    );
    
    return new VulnerabilitiesPanel(panel, extensionUri, vulnerabilities);
}

    dispose() {
        // Clean up disposables
        this.disposables.forEach(d => d.dispose());
        this.panel.dispose();
    }
}

module.exports = VulnerabilitiesPanel;