// Simple test script to verify export functionality

const fs = require('fs');
const path = require('path');

// Mock the VS Code API
const vscode = {
    window: {
        showSaveDialog: async (options) => {
            console.log('Save dialog options:', options);
            return { fsPath: path.join(__dirname, options.defaultUri.fsPath) };
        },
        showInformationMessage: (message) => {
            console.log('Information message:', message);
        },
        showErrorMessage: (message) => {
            console.log('Error message:', message);
        }
    },
    Uri: {
        file: (path) => ({ fsPath: path })
    }
};

// Mock vulnerability data
const vulnerabilities = [
    {
        type: 'SQL Injection',
        severity: 'High',
        line: 42,
        codeSnippet: 'const query = "SELECT * FROM users WHERE id = " + req.params.id;',
        message: 'Potential SQL injection vulnerability detected',
        context: 'SQL injection occurs when user input is directly concatenated into SQL queries without proper sanitization.',
        fix: 'Use parameterized queries or prepared statements.',
        detailedSolution: 'Replace direct string concatenation with parameterized queries.',
        documentation: 'https://cwe.mitre.org/data/definitions/89.html',
        cweId: 89,
        cweInfo: {
            name: 'Improper Neutralization of Special Elements used in an SQL Command',
            description: 'The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a database server.',
            mitigations: [
                {
                    Description: 'Use prepared statements and parameterized queries.',
                    Phase: 'Implementation'
                },
                {
                    Description: 'Use an ORM library.',
                    Phase: 'Implementation'
                }
            ],
            consequences: [
                {
                    Scope: ['Confidentiality', 'Integrity', 'Availability'],
                    Impact: ['Read Application Data', 'Modify Application Data', 'DoS: Crash, Exit, or Restart'],
                    Note: 'SQL injection can lead to unauthorized access to sensitive data.'
                }
            ],
            url: 'https://cwe.mitre.org/data/definitions/89.html'
        }
    },
    {
        type: 'Cross-Site Scripting (XSS)',
        severity: 'Medium',
        line: 57,
        codeSnippet: 'element.innerHTML = userInput;',
        message: 'Potential XSS vulnerability detected',
        context: 'Cross-site scripting vulnerabilities occur when user input is directly inserted into HTML without proper sanitization.',
        fix: 'Use textContent instead of innerHTML or sanitize the input.',
        detailedSolution: 'Replace innerHTML with textContent or use a library like DOMPurify to sanitize the input.',
        documentation: 'https://cwe.mitre.org/data/definitions/79.html',
        cweId: 79,
        cweInfo: {
            name: 'Improper Neutralization of Input During Web Page Generation',
            description: 'The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.',
            mitigations: [
                {
                    Description: 'Use a Content Security Policy (CSP) to restrict what content can be loaded on your site.',
                    Phase: 'Implementation'
                }
            ],
            consequences: [
                {
                    Scope: ['Confidentiality', 'Integrity'],
                    Impact: ['Execute Unauthorized Code or Commands', 'Bypass Protection Mechanism'],
                    Note: 'XSS can allow attackers to execute scripts in the victim\'s browser.'
                }
            ],
            url: 'https://cwe.mitre.org/data/definitions/79.html'
        }
    }
];

// Mock the export function
async function exportReport(format) {
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
        if (format === 'json') {
            // Create a clean JSON representation of the vulnerabilities
            const cleanVulnerabilities = vulnerabilities.map(vuln => {
                // Create a clean copy without circular references
                const cleanVuln = {
                    type: vuln.type || 'Unknown',
                    severity: vuln.severity || 'Medium',
                    line: vuln.line || 0,
                    codeSnippet: vuln.codeSnippet || '',
                    message: vuln.message || '',
                    context: vuln.context || '',
                    fix: vuln.fix || '',
                    detailedSolution: vuln.detailedSolution || '',
                    documentation: vuln.documentation || '',
                    cweId: vuln.cweId || null
                };
                
                // Add CWE information if available
                if (vuln.cweInfo) {
                    cleanVuln.cweInfo = {
                        name: vuln.cweInfo.name || '',
                        description: vuln.cweInfo.description || '',
                        mitigations: vuln.cweInfo.mitigations || [],
                        consequences: vuln.cweInfo.consequences || [],
                        url: vuln.cweInfo.url || ''
                    };
                }
                
                return cleanVuln;
            });
            
            content = JSON.stringify({
                metadata: {
                    generatedAt: new Date().toISOString(),
                    tool: "Vulnerability Scanner",
                    version: "1.0",
                    totalVulnerabilities: vulnerabilities.length
                },
                vulnerabilities: cleanVulnerabilities
            }, null, 2);
        }

        await fs.promises.writeFile(uri.fsPath, content);
        vscode.window.showInformationMessage(`Report exported successfully to ${uri.fsPath}`);
        console.log(`Report exported to: ${uri.fsPath}`);
    } catch (error) {
        console.error('Export error:', error);
        vscode.window.showErrorMessage(`Failed to export report: ${error.message}`);
    }
}

// Run the test
async function runTest() {
    console.log('Testing JSON export...');
    await exportReport('json');
    console.log('Test completed.');
}

runTest().catch(error => {
    console.error('Test failed:', error);
});
