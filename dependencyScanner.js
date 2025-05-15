const axios = require('axios');
const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

class DependencyScanner {
    static async scanProject(projectPath) {
        try {
            const packageJsonPath = path.join(projectPath, 'package.json');
            if (fs.existsSync(packageJsonPath)) {
                const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
                const dependencies = {
                    ...packageJson.dependencies,
                    ...packageJson.devDependencies
                };

                const vulnerabilities = [];
                
                // Check with Snyk API (you'll need an API key)
                if (vscode.workspace.getConfiguration('vulnerabilityScanner').get('enableSnyk')) {
                    const snykVulns = await this.checkWithSnyk(Object.keys(dependencies));
                    vulnerabilities.push(...snykVulns);
                }

                // Check with OWASP Dependency-Check
                if (vscode.workspace.getConfiguration('vulnerabilityScanner').get('enableOwaspDependencyCheck')) {
                    const owaspVulns = await this.runOwaspDependencyCheck(projectPath);
                    vulnerabilities.push(...owaspVulns);
                }

                return vulnerabilities;
            }
            return [];
        } catch (error) {
            console.error('Dependency scan error:', error);
            return [];
        }
    }

    static async checkWithSnyk(packages) {
        try {
            const response = await axios.post('https://snyk.io/api/v1/vulndb', {
                packages: packages
            }, {
                headers: {
                    'Authorization': `token ${process.env.SNYK_TOKEN}`
                }
            });

            return response.data.vulnerabilities.map(vuln => ({
                type: 'Vulnerable Dependency',
                severity: vuln.severity,
                message: `${vuln.package}@${vuln.version}: ${vuln.title}`,
                line: 0,
                codeSnippet: `${vuln.package}@${vuln.version}`,
                fix: `Upgrade to ${vuln.package}@${vuln.patchedVersions || vuln.latestVersion}`,
                documentation: vuln.url,
                cve: vuln.cve,
                cvssScore: vuln.cvssScore
            }));
        } catch (error) {
            console.error('Snyk API error:', error);
            return [];
        }
    }

    static async runOwaspDependencyCheck(projectPath) {
        // This would require having OWASP Dependency-Check installed
        // For a real implementation, you'd spawn a child process to run the CLI
        return []; // Placeholder
    }
}

module.exports = DependencyScanner;