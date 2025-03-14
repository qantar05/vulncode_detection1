const vscode = require('vscode');
const { scanForVulnerabilities } = require('./scanner');
const VulnerabilitiesPanel = require('./panel');

function activate(context) {
    console.log('Extension "vulnerability-scanner" is now active!');

    // Register the command
    const scanCommand = vscode.commands.registerCommand('vulnerabilityScanner.scan', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            const vulnerabilities = scanForVulnerabilities(editor.document);
            VulnerabilitiesPanel.createOrShow(context.extensionUri, vulnerabilities);
        }
    });

    // Add the command to the extension's subscriptions
    context.subscriptions.push(scanCommand);
}

function deactivate() {}

module.exports = { activate, deactivate };