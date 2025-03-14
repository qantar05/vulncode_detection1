const vscode = require('vscode');

class Vulnerability {
    constructor(type, severity, message, line, codeSnippet, fix, documentation) {
        this.type = type;
        this.severity = severity;
        this.message = message;
        this.line = line;
        this.codeSnippet = codeSnippet;
        this.fix = fix;
        this.documentation = documentation;
    }
}

function scanForVulnerabilities(document) {
    const vulnerabilities = [];
    const text = document.getText();

    // Detect SQL Injection
    const sqlInjectionPattern = /(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b).*(\bWHERE\b.*=.*['"].*['"])/gi;
    let match;
    while ((match = sqlInjectionPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'SQL Injection',
            'High',
            'Potential SQL Injection detected',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use parameterized queries or prepared statements.',
            'https://owasp.org/www-community/attacks/SQL_Injection'
        ));
    }

    // Detect XSS
    const xssPattern = /(\bdocument\.write\b|\binnerHTML\b).*['"][^'"]*['"]/gi;
    while ((match = xssPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Cross-Site Scripting (XSS)',
            'High',
            'Potential XSS detected',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use proper escaping or sanitization for user inputs.',
            'https://owasp.org/www-community/attacks/xss/'
        ));
    }

    // Detect Insecure Use of eval()
    const evalPattern = /\beval\s*\(/gi;
    while ((match = evalPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Insecure Use of eval()',
            'High',
            'Use of eval() detected',
            document.positionAt(match.index).line + 1,
            match[0],
            'Avoid using eval(). Use safer alternatives like JSON.parse() or Function().',
            'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval'
        ));
    }

    // Detect Hardcoded Secrets
    const secretPattern = /(apiKey|password|token|secret)\s*=\s*['"][^'"]*['"]/gi;
    while ((match = secretPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Hardcoded Secret',
            'Medium',
            'Hardcoded secret detected',
            document.positionAt(match.index).line + 1,
            match[0],
            'Store secrets in environment variables or secure vaults.',
            'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'
        ));
    }

    // Detect Insecure Randomness
    const randomPattern = /Math\.random\(\)/gi;
    while ((match = randomPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Insecure Randomness',
            'Medium',
            'Use of Math.random() detected',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use crypto.getRandomValues() for secure randomness.',
            'https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues'
        ));
    }

    // Detect Unvalidated Redirects
    const redirectPattern = /(window\.location|document\.location)\s*=\s*[^;]*/gi;
    while ((match = redirectPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Unvalidated Redirect',
            'Medium',
            'Unvalidated redirect detected',
            document.positionAt(match.index).line + 1,
            match[0],
            'Validate and sanitize user input before redirecting.',
            'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards'
        ));
    }

    return vulnerabilities;
}

module.exports = { Vulnerability, scanForVulnerabilities };