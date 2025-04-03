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
        // Count vulnerabilities by severity for the pie chart
        const severityCounts = { High: 0, Medium: 0, Low: 0 };
        vulnerabilities.forEach(vuln => severityCounts[vuln.severity]++);

        // Generate pie chart data
        const pieChartData = {
            labels: ['High', 'Medium', 'Low'],
            datasets: [{
                data: [severityCounts.High, severityCounts.Medium, severityCounts.Low],
                backgroundColor: ['#dc3545', '#ffc107', '#28a745'],
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
                }
                .vulnerability {
                    background: #fff;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 15px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
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
                .severity-high {
                    color: #dc3545;
                }
                .severity-medium {
                    color: #ffc107;
                }
                .severity-low {
                    color: #28a745;
                }
                .chart-container {
                    margin-bottom: 30px;
                    text-align: center;
                }
                .chart-container canvas {
                    max-width: 300px;
                    margin: 0 auto;
                }
                .collapsible {
                    cursor: pointer;
                    padding: 10px;
                    border: none;
                    text-align: left;
                    outline: none;
                    font-size: 1em;
                    background-color: #f1f1f1;
                    border-radius: 5px;
                    margin-bottom: 10px;
                }
                .collapsible:hover {
                    background-color: #ddd;
                }
                .content {
                    padding: 0 18px;
                    display: none;
                    overflow: hidden;
                    background-color: #f9f9f9;
                    border-radius: 5px;
                }
                .cve-info {
                    background: #e9ecef;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 10px;
                }
                .detailed-solution {
                    background: #e9ecef;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 10px;
                }
                .context {
                    background: #e9ecef;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 10px;
                }
            </style>
        `;

        // Generate collapsible vulnerability list
        const vulnerabilitiesList = vulnerabilities.map((vuln, index) => `
            <div class="vulnerability">
                <button class="collapsible">
                    <span class="icon">${this.getSeverityIcon(vuln.severity)}</span>
                    <span class="severity-${vuln.severity.toLowerCase()}">${vuln.type} (${vuln.severity})</span>
                </button>
                <div class="content">
                    <p><strong>Message:</strong> ${vuln.message}</p>
                    <p><strong>Line:</strong> ${vuln.line}</p>
                    <pre>${vuln.codeSnippet}</pre>
                    ${vuln.fix ? `<p><strong>Quick Fix:</strong> ${vuln.fix}</p>` : ''}
                    ${vuln.cve ? `<div class="cve-info"><strong>CVE:</strong> <a href="https://nvd.nist.gov/vuln/detail/${vuln.cve}" target="_blank">${vuln.cve}</a></div>` : ''}
                    ${vuln.detailedSolution ? `<div class="detailed-solution"><strong>Detailed Solution:</strong><pre>${vuln.detailedSolution}</pre></div>` : ''}
                    ${vuln.context ? `<div class="context"><strong>Context:</strong><p>${vuln.context}</p></div>` : ''}
                    ${vuln.documentation ? `<p><a href="${vuln.documentation}" target="_blank">Learn More</a></p>` : ''}
                </div>
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
                <h1>Detected Vulnerabilities</h1>

                <!-- Pie Chart -->
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>

                <!-- Vulnerabilities List -->
                ${vulnerabilitiesList}

                <script>
                    // Render pie chart
                    const ctx = document.getElementById('severityChart').getContext('2d');
                    const severityChart = new Chart(ctx, {
                        type: 'pie',
                        data: ${JSON.stringify(pieChartData)},
                        options: {
                            responsive: true,
                            plugins: {
                                legend: {
                                    position: 'bottom',
                                },
                            },
                        },
                    });

                    // Collapsible functionality
                    const collapsibles = document.getElementsByClassName('collapsible');
                    for (let i = 0; i < collapsibles.length; i++) {
                        collapsibles[i].addEventListener('click', function() {
                            this.classList.toggle('active');
                            const content = this.nextElementSibling;
                            if (content.style.display === 'block') {
                                content.style.display = 'none';
                            } else {
                                content.style.display = 'block';
                            }
                        });
                    }
                </script>
            </body>
            </html>
        `;
    }

    // Get severity icon based on severity level
    getSeverityIcon(severity) {
        switch (severity) {
            case 'High':
                return '🔴';
            case 'Medium':
                return '🟡';
            case 'Low':
                return '🟢';
            default:
                return '⚪';
        }
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