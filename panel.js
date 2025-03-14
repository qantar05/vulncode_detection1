const vscode = require('vscode');
const { Vulnerability } = require('./scanner');

class VulnerabilitiesPanel {
    static viewType = 'vulnerabilityScanner.panel';

    constructor(panel, extensionUri, vulnerabilities) {
        this.panel = panel;
        this.extensionUri = extensionUri;
        this.panel.webview.html = this.getHtmlForWebview(vulnerabilities);
    }

    getHtmlForWebview(vulnerabilities) {
        const style = `
            <style>
                body {
                    font-family: Arial, sans-serif;
                    padding: 20px;
                    background-color: #f9f9f9;
                }
                h1 {
                    color: #333;
                }
                .vulnerability {
                    background: #fff;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 15px;
                }
                .vulnerability h3 {
                    margin-top: 0;
                    color: #d9534f;
                }
                .vulnerability pre {
                    background: #f5f5f5;
                    padding: 10px;
                    border-radius: 3px;
                    overflow-x: auto;
                }
                .vulnerability a {
                    color: #0275d8;
                    text-decoration: none;
                }
                .vulnerability a:hover {
                    text-decoration: underline;
                }
            </style>
        `;

        const vulnerabilitiesList = vulnerabilities.map(vuln => `
            <div class="vulnerability">
                <h3>${vuln.type} (${vuln.severity})</h3>
                <p><strong>Message:</strong> ${vuln.message}</p>
                <p><strong>Line:</strong> ${vuln.line}</p>
                <pre>${vuln.codeSnippet}</pre>
                ${vuln.fix ? `<p><strong>Fix:</strong> ${vuln.fix}</p>` : ''}
                ${vuln.documentation ? `<p><a href="${vuln.documentation}" target="_blank">Learn More</a></p>` : ''}
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
            </head>
            <body>
                <h1>Detected Vulnerabilities</h1>
                ${vulnerabilitiesList}
            </body>
            </html>
        `;
    }

    static createOrShow(extensionUri, vulnerabilities) {
        const column = vscode.window.activeTextEditor ? vscode.window.activeTextEditor.viewColumn : undefined;
        const panel = vscode.window.createWebviewPanel(
            VulnerabilitiesPanel.viewType,
            'Vulnerabilities Report',
            column || vscode.ViewColumn.One,
            { enableScripts: true }
        );
        new VulnerabilitiesPanel(panel, extensionUri, vulnerabilities);
    }
}

module.exports = VulnerabilitiesPanel;