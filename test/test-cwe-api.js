// Simple test script to verify CWE API integration

const cweApi = require('../cweApi');

// Test CWE IDs to check
const cweIds = [
    89,  // SQL Injection
    79,  // XSS
    22,  // Path Traversal
    798, // Hard-coded Credentials
    327, // Weak Cryptography
    352, // CSRF
    918, // SSRF
    330, // Weak Randomness
    434, // Unrestricted Upload
    190, // Integer Overflow
    311, // Missing Encryption
    95   // Eval Injection
];

async function testCWEApi() {
    console.log('Testing CWE API integration...\n');

    for (const cweId of cweIds) {
        try {
            console.log(`Fetching information for CWE-${cweId}...`);
            const cweInfo = await cweApi.getSimplifiedCWEInfo(cweId);
            
            console.log(`CWE-${cweId}: ${cweInfo.name}`);
            console.log(`Description: ${cweInfo.description.substring(0, 100)}...`);
            console.log(`Mitigations: ${cweInfo.mitigations.length}`);
            console.log(`Consequences: ${cweInfo.consequences.length}`);
            
            // Print first mitigation if available
            if (cweInfo.mitigations.length > 0) {
                const firstMitigation = cweInfo.mitigations[0];
                console.log('First mitigation:');
                if (typeof firstMitigation === 'string') {
                    console.log(`  ${firstMitigation.substring(0, 100)}...`);
                } else if (firstMitigation.Description) {
                    console.log(`  ${firstMitigation.Description.substring(0, 100)}...`);
                }
            }
            
            // Print first consequence if available
            if (cweInfo.consequences.length > 0) {
                const firstConsequence = cweInfo.consequences[0];
                console.log('First consequence:');
                if (firstConsequence.Scope) {
                    console.log(`  Scope: ${firstConsequence.Scope.join(', ')}`);
                }
                if (firstConsequence.Impact) {
                    console.log(`  Impact: ${firstConsequence.Impact.join(', ')}`);
                }
                if (firstConsequence.Note) {
                    console.log(`  Note: ${firstConsequence.Note.substring(0, 100)}...`);
                }
            }
            
            console.log('-----------------------------------\n');
        } catch (error) {
            console.error(`Error fetching CWE-${cweId}:`, error.message);
        }
    }
}

// Run the test
testCWEApi().catch(error => {
    console.error('Test failed:', error);
});
