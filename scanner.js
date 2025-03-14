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
    const language = document.languageId; // Get the language of the file

    // JavaScript Vulnerabilities
    if (language === 'javascript') {
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

        // Detect Prototype Pollution
        const prototypePollutionPattern = /(\b__proto__\b|\bconstructor\b|\bprototype\b)\s*=\s*[^;]*/gi;
        while ((match = prototypePollutionPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Prototype Pollution',
                'High',
                'Potential prototype pollution detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid modifying object prototypes directly. Use safer alternatives like Object.assign().',
                'https://owasp.org/www-community/attacks/Prototype_Pollution'
            ));
        }

        // Detect Insecure Use of localStorage
        const localStoragePattern = /localStorage\.setItem\s*\([^)]*['"][^'"]*['"]/gi;
        while ((match = localStoragePattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Insecure Use of localStorage',
                'Medium',
                'Potential insecure use of localStorage detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid storing sensitive data in localStorage. Use secure storage mechanisms.',
                'https://owasp.org/www-community/vulnerabilities/Insecure_Storage'
            ));
        }
    }

    // Java Vulnerabilities
    if (language === 'java') {
        // Detect Insecure Deserialization
        const deserializationPattern = /(ObjectInputStream|readObject)\s*\([^)]*\)/gi;
        let match; // Declare 'match' here
        while ((match = deserializationPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Insecure Deserialization',
                'High',
                'Potential insecure deserialization detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid deserializing untrusted data. Use safer alternatives like JSON or XML parsers.',
                'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data'
            ));
        }

        // Detect Command Injection
        const commandInjectionPattern = /Runtime\.getRuntime\(\).exec\s*\([^)]*['"][^'"]*['"]/gi;
        while ((match = commandInjectionPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Command Injection',
                'High',
                'Potential command injection detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid using user input directly in command execution. Use safer alternatives.',
                'https://owasp.org/www-community/attacks/Command_Injection'
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
    }

    // Python Vulnerabilities
    if (language === 'python') {
        // Detect Shell Injection
        const shellInjectionPattern = /(os\.system|subprocess\.call|subprocess\.Popen)\s*\([^)]*['"][^'"]*['"]/gi;
        let match; // Declare 'match' here
        while ((match = shellInjectionPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Shell Injection',
                'High',
                'Potential shell injection detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid using user input directly in shell commands. Use safer alternatives like subprocess with arguments.',
                'https://owasp.org/www-community/attacks/Command_Injection'
            ));
        }

        // Detect Insecure Use of eval
        const evalPattern = /\beval\s*\(/gi;
        while ((match = evalPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Insecure Use of eval()',
                'High',
                'Use of eval() detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid using eval(). Use safer alternatives like ast.literal_eval().',
                'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval'
            ));
        }

        // Detect Insecure File Operations
        const fileOperationPattern = /(open|read|write)\s*\([^)]*['"][^'"]*['"]/gi;
        while ((match = fileOperationPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Insecure File Operation',
                'Medium',
                'Potential insecure file operation detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Validate and sanitize file paths before performing file operations.',
                'https://owasp.org/www-community/vulnerabilities/Path_Traversal'
            ));
        }
    }

    return vulnerabilities;
}

module.exports = { Vulnerability, scanForVulnerabilities };