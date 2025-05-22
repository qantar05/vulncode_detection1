// Simple test script to verify regex patterns against debug.js

const fs = require('fs');
const path = require('path');

// Read the debug.js file
const debugJsPath = path.join(__dirname, 'debug.js');
const debugJsContent = fs.readFileSync(debugJsPath, 'utf8');

// Define the patterns we want to test
const patterns = [
    {
        name: 'Hard-coded Credentials (CWE-259/CWE-798)',
        pattern: /(?:const|let|var)\s+(?:\w+(?:password|passwd|pwd|secret|key|token|credential|auth))\s*=\s*['"][^'"]+['"]/gi,
        cweId: 798
    },
    {
        name: 'Weak Cryptography (CWE-327)',
        pattern: /crypto\.createCipher\s*\(\s*['"](?:des|rc4|md5)['"]/gi,
        cweId: 327
    },
    {
        name: 'CSRF (CWE-352)',
        pattern: /app\.(?:post|put|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*\([^)]*\)\s*=>/gi,
        cweId: 352
    },
    {
        name: 'Path Traversal (CWE-22)',
        pattern: /(?:fs|require\(['"]fs['"]\))\.(?:readFileSync|readFile|writeFileSync|writeFile|appendFileSync|appendFile|createReadStream|createWriteStream)\s*\(\s*(?:[^)]*\+\s*|`[^`]*\$\{)[^)]*\)/gi,
        cweId: 22
    },
    {
        name: 'SSRF (CWE-918)',
        pattern: /(?:fetch|axios|http\.get|https\.get|request|superagent)\s*\(\s*(?:[^)]*\+\s*|`[^`]*\$\{|req\.(?:query|params|body)\.)[^)]*\)/gi,
        cweId: 918
    },
    {
        name: 'SSRF - Direct URL (CWE-918)',
        pattern: /(?:function|const|let|var)\s+\w+\s*\([^)]*\)\s*\{[^}]*(?:fetch|axios|http\.get|https\.get|request)\s*\(\s*(?:url|req\.query\.url)/gi,
        cweId: 918
    },
    {
        name: 'Weak Randomness (CWE-330)',
        pattern: /Math\.random\s*\(\s*\)/gi,
        cweId: 330
    },
    {
        name: 'Unrestricted File Upload (CWE-434)',
        pattern: /(?:\.mv\s*\(|multer|formidable|busboy|multiparty|file\.mv|req\.files)/gi,
        cweId: 434
    },
    {
        name: 'Integer Overflow (CWE-190)',
        pattern: /(?:(?:var|let|const)\s+\w+\s*=\s*\d+|[\w.]+\s*\+=\s*[\w.]+)(?![\s\S]*(?:if\s*\(\s*[\w.]+\s*(?:>|<|>=|<=)\s*(?:Number\.MAX_SAFE_INTEGER|Number\.MIN_SAFE_INTEGER|\d+)\s*\)))/gi,
        cweId: 190
    },
    {
        name: 'Missing Encryption (CWE-311)',
        pattern: /(?:localStorage\.setItem|sessionStorage\.setItem)\s*\(\s*['"][^'"]*(?:password|token|secret|key|auth|credential|ssn|dob|credit|card|social|security|personal|private|sensitive)['"]/gi,
        cweId: 311
    },
    {
        name: 'Missing Encryption - JSON.stringify (CWE-311)',
        pattern: /JSON\.stringify\s*\(\s*\{[^}]*(?:ssn|dob|credit|card|social|security|personal|private|sensitive)[^}]*\}\s*\)/gi,
        cweId: 311
    },
    {
        name: 'Insecure eval() (CWE-95)',
        pattern: /\beval\s*\(|new Function\s*\(|setTimeout\s*\(\s*['"][^'"]*['"]/gi,
        cweId: 95
    }
];

// Test each pattern
console.log('Testing patterns against debug.js...\n');

let totalMatches = 0;
const matchesByLine = {};

patterns.forEach(patternInfo => {
    let match;
    let patternMatches = 0;

    // Reset the pattern's lastIndex to start from the beginning
    patternInfo.pattern.lastIndex = 0;

    while ((match = patternInfo.pattern.exec(debugJsContent)) !== null) {
        patternMatches++;

        // Calculate line number
        const lineNumber = debugJsContent.substring(0, match.index).split('\n').length;

        // Get the matched line content
        const lines = debugJsContent.split('\n');
        const lineContent = lines[lineNumber - 1].trim();

        // Store the match information
        if (!matchesByLine[lineNumber]) {
            matchesByLine[lineNumber] = [];
        }

        matchesByLine[lineNumber].push({
            pattern: patternInfo.name,
            cweId: patternInfo.cweId,
            content: lineContent
        });
    }

    console.log(`${patternInfo.name} (CWE-${patternInfo.cweId}): ${patternMatches} matches`);
    totalMatches += patternMatches;
});

console.log(`\nTotal matches: ${totalMatches}`);
console.log('\nMatches by line:');

// Sort the lines numerically
const sortedLines = Object.keys(matchesByLine).map(Number).sort((a, b) => a - b);

sortedLines.forEach(lineNumber => {
    console.log(`\nLine ${lineNumber}:`);
    matchesByLine[lineNumber].forEach(match => {
        console.log(`  - ${match.pattern} (CWE-${match.cweId}): ${match.content}`);
    });
});
