const vscode = require('vscode');

/**
 * This script can be used to test the vulnerability scanner extension
 * Run it using the Debug Console in VS Code
 */

async function testExtension() {
    console.log('Testing vulnerability scanner extension...');
    
    // Get all available commands
    const commands = await vscode.commands.getCommands(true);
    const vulnCommands = commands.filter(cmd => cmd.includes('vulnerabilityScanner'));
    console.log('Available vulnerability scanner commands:', vulnCommands);
    
    // Check if the extension is activated
    const extension = vscode.extensions.getExtension('your-unique-publisher-name.vulnerability-scanner');
    if (!extension) {
        console.error('Extension not found!');
        return;
    }
    
    console.log('Extension found:', extension.id);
    console.log('Extension is active:', extension.isActive);
    
    // Activate the extension if not already active
    if (!extension.isActive) {
        console.log('Activating extension...');
        await extension.activate();
        console.log('Extension activated:', extension.isActive);
    }
    
    // Open a test file
    const testFile = vscode.Uri.file(`${__dirname}/debug.js`);
    const document = await vscode.workspace.openTextDocument(testFile);
    await vscode.window.showTextDocument(document);
    
    // Execute the scan command
    console.log('Executing scan command...');
    await vscode.commands.executeCommand('vulnerabilityScanner.scan');
    
    console.log('Test completed!');
}

// Export the test function
module.exports = {
    testExtension
};
