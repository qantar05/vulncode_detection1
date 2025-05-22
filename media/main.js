// Get the VS Code API
const vscode = acquireVsCodeApi();

// Handle messages from the extension
window.addEventListener('message', event => {
    const message = event.data;
    switch (message.command) {
        case 'updateVulnerabilities':
            // Update the vulnerabilities list
            updateVulnerabilities(message.vulnerabilities);
            break;
    }
});

// Apply auto-fix for a vulnerability
function applyFix(index) {
    vscode.postMessage({
        command: 'applyFix',
        index: index
    });
}

// Show documentation for a vulnerability
function showDocumentation(url) {
    vscode.postMessage({
        command: 'showDocumentation',
        url: url
    });
}

// Simulate an attack for a vulnerability
function simulateAttack(index) {
    vscode.postMessage({
        command: 'simulateAttack',
        index: index
    });
}

// Export the vulnerability report
function exportReport(format) {
    vscode.postMessage({
        command: 'exportReport',
        format: format
    });
}

// Trigger a rescan of the project
function rescan() {
    vscode.postMessage({
        command: 'rescan'
    });
}

// Show test cases for a vulnerability
function showTestCases(index) {
    vscode.postMessage({
        command: 'showTestCases',
        index: index
    });
}

// Filter vulnerabilities based on severity, type, and search term
function filterVulnerabilities() {
    const severityFilter = document.getElementById('severityFilter').value;
    const typeFilter = document.getElementById('typeFilter').value;
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();

    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
    const vulnerabilityElements = vulnerabilitiesList.getElementsByClassName('vulnerability');

    for (let i = 0; i < vulnerabilityElements.length; i++) {
        const vuln = vulnerabilityElements[i];
        const severity = vuln.getAttribute('data-severity');
        const type = vuln.getAttribute('data-type');
        const text = vuln.textContent.toLowerCase();

        const severityMatch = severityFilter === 'all' || severity === severityFilter;
        const typeMatch = typeFilter === 'all' || type === typeFilter;
        const searchMatch = searchTerm === '' || text.includes(searchTerm);

        if (severityMatch && typeMatch && searchMatch) {
            vuln.style.display = '';
        } else {
            vuln.style.display = 'none';
        }
    }

    // Update count of displayed vulnerabilities
    const visibleCount = Array.from(vulnerabilityElements).filter(el => el.style.display !== 'none').length;
    const heading = document.querySelector('.vulnerabilities h2');
    if (heading) {
        heading.textContent = `Found ${visibleCount} Vulnerabilities`;
    }
}

// Dummy function for updateVulnerabilities (optional, for completeness)
function updateVulnerabilities(vulnerabilities) {
    // This function can be implemented to update the DOM if vulnerabilities are updated from the extension
    // For now, it's a placeholder
}

// This function is provided by VS Code when running in a webview
// We only need this placeholder for development/testing outside of VS Code
// In the actual extension, VS Code provides this function
try {
    // Try to use the VS Code API if available
    acquireVsCodeApi();
} catch (e) {
    console.warn('Running outside of VS Code environment');
}
