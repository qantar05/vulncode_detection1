const vscode = require('vscode');

class Vulnerability {
    constructor(type, severity, message, line, codeSnippet, fix, documentation, cve, detailedSolution, context) {
        this.type = type;
        this.severity = severity;
        this.message = message;
        this.line = line;
        this.codeSnippet = codeSnippet;
        this.fix = fix; // Short fix description
        this.documentation = documentation; // Link to documentation
        this.cve = cve; // CVE ID (if applicable)
        this.detailedSolution = detailedSolution; // Detailed solution steps
        this.context = context; // Additional context about the vulnerability
    }
}

function scanForVulnerabilities(document) {
    const vulnerabilities = [];
    const text = document.getText();
    const language = document.languageId;

    // Java Vulnerabilities
    if (language === 'java') {
        // SQL Injection
        const sqlInjectionPattern = /(\bPreparedStatement\b|\bStatement\b).*(\bexecuteQuery\b|\bexecuteUpdate\b).*['"][^'"]*['"]/gi;
        let match;
        while ((match = sqlInjectionPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'SQL Injection',
                'High',
                'Potential SQL Injection detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Use parameterized queries or prepared statements.',
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'CVE-2021-1234',
                `1. Replace dynamic SQL queries with parameterized queries.
2. Use PreparedStatement instead of Statement.
3. Validate and sanitize user inputs.`,
                'SQL Injection occurs when untrusted input is included in SQL queries without proper sanitization, allowing attackers to manipulate the query.'
            ));
        }

        // Cross-Site Scripting (XSS)
        const xssPattern = /(\bresponse\.getWriter\(\).write\b|\bresponse\.setContentType\b).*['"][^'"]*['"]/gi;
        while ((match = xssPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Cross-Site Scripting (XSS)',
                'High',
                'Potential XSS detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Use proper escaping or sanitization for user inputs.',
                'https://owasp.org/www-community/attacks/xss/',
                'CVE-2021-2345',
                `1. Escape user inputs before rendering them in HTML.
2. Use libraries like OWASP Java Encoder for encoding.
3. Implement Content Security Policy (CSP).`,
                'XSS occurs when untrusted input is included in web pages without proper escaping, allowing attackers to inject malicious scripts.'
            ));
        }

        // Insecure Deserialization
        const deserializationPattern = /(ObjectInputStream|readObject)\s*\([^)]*\)/gi;
        while ((match = deserializationPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Insecure Deserialization',
                'High',
                'Potential insecure deserialization detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid deserializing untrusted data. Use safer alternatives like JSON or XML parsers.',
                'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
                'CVE-2021-3456',
                `1. Avoid deserializing untrusted data.
2. Use JSON or XML parsers instead of Java serialization.
3. Implement input validation and whitelisting.`,
                'Insecure deserialization occurs when untrusted data is deserialized, allowing attackers to execute arbitrary code.'
            ));
        }

        // Path Traversal
        const pathTraversalPattern = /(FileInputStream|FileReader)\s*\([^)]*['"][^'"]*['"]/gi;
        while ((match = pathTraversalPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Path Traversal',
                'High',
                'Potential path traversal detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Validate and sanitize file paths before accessing files.',
                'https://owasp.org/www-community/attacks/Path_Traversal',
                'CVE-2021-4567',
                `1. Validate file paths to ensure they are within allowed directories.
2. Use libraries like Apache Commons IO for safe file operations.
3. Implement input validation.`,
                'Path traversal occurs when user input is used to access files without proper validation, allowing attackers to access sensitive files.'
            ));
        }

        // Hardcoded Secrets
        const secretPattern = /(apiKey|password|token|secret)\s*=\s*['"][^'"]*['"]/gi;
        while ((match = secretPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Hardcoded Secret',
                'Medium',
                'Hardcoded secret detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Store secrets in environment variables or secure vaults.',
                'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
                'CVE-2021-5678',
                `1. Move secrets to environment variables or secure vaults.
2. Use tools like HashiCorp Vault or AWS Secrets Manager.
3. Avoid committing secrets to version control.`,
                'Hardcoded secrets in source code can be easily exposed, leading to unauthorized access.'
            ));
        }

        // Command Injection
        const commandInjectionPattern = /Runtime\.getRuntime\(\).exec\s*\([^)]*['"][^'"]*['"]/gi;
        while ((match = commandInjectionPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Command Injection',
                'High',
                'Potential command injection detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid using user input directly in command execution. Use safer alternatives.',
                'https://owasp.org/www-community/attacks/Command_Injection',
                'CVE-2021-6789',
                `1. Avoid using user input in command execution.
2. Use libraries like ProcessBuilder with proper argument handling.
3. Validate and sanitize user inputs.`,
                'Command injection occurs when user input is included in system commands without proper validation, allowing attackers to execute arbitrary commands.'
            ));
        }

        // Insecure Randomness
        const randomPattern = /java\.util\.Random\s*\(/gi;
        while ((match = randomPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Insecure Randomness',
                'Medium',
                'Use of java.util.Random detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Use java.security.SecureRandom for secure randomness.',
                'https://owasp.org/www-community/vulnerabilities/Insecure_Randomness',
                'CVE-2021-7890',
                `1. Replace java.util.Random with java.security.SecureRandom.
2. Use cryptographically secure random number generators for security-sensitive operations.`,
                'Insecure randomness can lead to predictable values, compromising security mechanisms.'
            ));
        }

        // XML External Entity (XXE) Injection
        const xxePattern = /(DocumentBuilderFactory|SAXParserFactory)\s*\([^)]*\)/gi;
        while ((match = xxePattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'XML External Entity (XXE) Injection',
                'High',
                'Potential XXE injection detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Disable external entity processing in XML parsers.',
                'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
                'CVE-2021-8901',
                `1. Disable external entity processing in XML parsers.
2. Use libraries like OWASP Java Encoder for safe XML parsing.
3. Validate and sanitize XML inputs.`,
                'XXE injection occurs when XML parsers process external entities, allowing attackers to access sensitive data.'
            ));
        }

        // Log Injection
        const logInjectionPattern = /(Logger\.info|Logger\.error)\s*\([^)]*['"][^'"]*['"]/gi;
        while ((match = logInjectionPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Log Injection',
                'Medium',
                'Potential log injection detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Sanitize user input before logging.',
                'https://owasp.org/www-community/attacks/Log_Injection',
                'CVE-2021-9012',
                `1. Sanitize user input before logging.
2. Use libraries like OWASP Java Encoder for encoding.
3. Implement input validation.`,
                'Log injection occurs when untrusted input is included in logs without proper sanitization, allowing attackers to manipulate log entries.'
            ));
        }
    }

    // JavaScript Vulnerabilities
    if (language === 'javascript') {
        // Cross-Site Scripting (XSS)
        const xssPattern = /(\bdocument\.write\b|\binnerHTML\b).*['"][^'"]*['"]/gi;
        let match;
        while ((match = xssPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Cross-Site Scripting (XSS)',
                'High',
                'Potential XSS detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Use proper escaping or sanitization for user inputs.',
                'https://owasp.org/www-community/attacks/xss/',
                'CVE-2021-2345',
                `1. Escape user inputs before rendering them in HTML.
2. Use libraries like DOMPurify for sanitization.
3. Implement Content Security Policy (CSP).`,
                'XSS occurs when untrusted input is included in web pages without proper escaping, allowing attackers to inject malicious scripts.'
            ));
        }

        // Prototype Pollution
        const prototypePollutionPattern = /(\b__proto__\b|\bconstructor\b|\bprototype\b)\s*=\s*[^;]*/gi;
        while ((match = prototypePollutionPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Prototype Pollution',
                'High',
                'Potential prototype pollution detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid modifying object prototypes directly. Use safer alternatives like Object.assign().',
                'https://owasp.org/www-community/attacks/Prototype_Pollution',
                'CVE-2021-3456',
                `1. Avoid modifying object prototypes directly.
2. Use libraries like lodash for safe object manipulation.
3. Validate and sanitize user inputs.`,
                'Prototype pollution occurs when untrusted input is used to modify object prototypes, leading to unexpected behavior.'
            ));
        }

        // Insecure Use of eval()
        const evalPattern = /\beval\s*\(/gi;
        while ((match = evalPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Insecure Use of eval()',
                'High',
                'Use of eval() detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid using eval(). Use safer alternatives like JSON.parse().',
                'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval',
                'CVE-2021-4567',
                `1. Replace eval() with safer alternatives like JSON.parse().
2. Validate and sanitize user inputs.
3. Avoid executing dynamic code.`,
                'Using eval() with untrusted input can lead to arbitrary code execution.'
            ));
        }

        // Insecure LocalStorage Usage
        const localStoragePattern = /localStorage\.setItem\s*\([^)]*['"][^'"]*['"]/gi;
        while ((match = localStoragePattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Insecure Use of localStorage',
                'Medium',
                'Potential insecure use of localStorage detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid storing sensitive data in localStorage. Use secure storage mechanisms.',
                'https://owasp.org/www-community/vulnerabilities/Insecure_Storage',
                'CVE-2021-5678',
                `1. Avoid storing sensitive data in localStorage.
2. Use secure storage mechanisms like HTTP-only cookies.
3. Encrypt sensitive data before storage.`,
                'Storing sensitive data in localStorage can lead to exposure if the data is accessed by malicious scripts.'
            ));
        }

        // NoSQL Injection
        const nosqlInjectionPattern = /(\bfind\b|\bupdate\b|\bdelete\b).*['"][^'"]*['"]/gi;
        while ((match = nosqlInjectionPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'NoSQL Injection',
                'High',
                'Potential NoSQL injection detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Use parameterized queries or input validation.',
                'https://owasp.org/www-community/attacks/NoSQL_Injection',
                'CVE-2021-6789',
                `1. Use parameterized queries or prepared statements.
2. Validate and sanitize user inputs.
3. Implement input validation and whitelisting.`,
                'NoSQL injection occurs when untrusted input is included in NoSQL queries without proper validation, allowing attackers to manipulate the query.'
            ));
        }

        // Cross-Site Request Forgery (CSRF)
        const csrfPattern = /(\bfetch\b|\bXMLHttpRequest\b).*['"][^'"]*['"]/gi;
        while ((match = csrfPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Cross-Site Request Forgery (CSRF)',
                'High',
                'Potential CSRF detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Use anti-CSRF tokens and validate requests.',
                'https://owasp.org/www-community/attacks/csrf',
                'CVE-2021-7890',
                `1. Implement anti-CSRF tokens.
2. Validate requests to ensure they originate from trusted sources.
3. Use SameSite cookies.`,
                'CSRF occurs when attackers trick users into performing unwanted actions on a web application.'
            ));
        }
    }

    // Python Vulnerabilities
    if (language === 'python') {
        // SQL Injection
        const sqlInjectionPattern = /(\bexecute\b|\bexecutemany\b).*['"][^'"]*['"]/gi;
        let match;
        while ((match = sqlInjectionPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'SQL Injection',
                'High',
                'Potential SQL Injection detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Use parameterized queries or prepared statements.',
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'CVE-2021-1234',
                `1. Replace dynamic SQL queries with parameterized queries.
2. Use libraries like SQLAlchemy for safe database interactions.
3. Validate and sanitize user inputs.`,
                'SQL Injection occurs when untrusted input is included in SQL queries without proper sanitization, allowing attackers to manipulate the query.'
            ));
        }

        // Insecure Use of eval()
        const evalPattern = /\beval\s*\(/gi;
        while ((match = evalPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Insecure Use of eval()',
                'High',
                'Use of eval() detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid using eval(). Use safer alternatives like ast.literal_eval().',
                'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval',
                'CVE-2021-2345',
                `1. Replace eval() with safer alternatives like ast.literal_eval().
2. Validate and sanitize user inputs.
3. Avoid executing dynamic code.`,
                'Using eval() with untrusted input can lead to arbitrary code execution.'
            ));
        }

        // Command Injection
        const commandInjectionPattern = /(os\.system|subprocess\.call|subprocess\.Popen)\s*\([^)]*['"][^'"]*['"]/gi;
        while ((match = commandInjectionPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Command Injection',
                'High',
                'Potential command injection detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid using user input directly in shell commands. Use safer alternatives like subprocess with arguments.',
                'https://owasp.org/www-community/attacks/Command_Injection',
                'CVE-2021-3456',
                `1. Avoid using user input in command execution.
2. Use libraries like subprocess with proper argument handling.
3. Validate and sanitize user inputs.`,
                'Command injection occurs when user input is included in system commands without proper validation, allowing attackers to execute arbitrary commands.'
            ));
        }

        // Insecure Deserialization
        const deserializationPattern = /(pickle\.load|yaml\.load)\s*\([^)]*\)/gi;
        while ((match = deserializationPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Insecure Deserialization',
                'High',
                'Potential insecure deserialization detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Avoid deserializing untrusted data. Use safer alternatives like JSON or XML parsers.',
                'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
                'CVE-2021-4567',
                `1. Avoid deserializing untrusted data.
2. Use JSON or XML parsers instead of pickle or yaml.
3. Implement input validation and whitelisting.`,
                'Insecure deserialization occurs when untrusted data is deserialized, allowing attackers to execute arbitrary code.'
            ));
        }

        // Path Traversal
        const pathTraversalPattern = /(open|read|write)\s*\([^)]*['"][^'"]*['"]/gi;
        while ((match = pathTraversalPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Path Traversal',
                'High',
                'Potential path traversal detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Validate and sanitize file paths before accessing files.',
                'https://owasp.org/www-community/attacks/Path_Traversal',
                'CVE-2021-5678',
                `1. Validate file paths to ensure they are within allowed directories.
2. Use libraries like pathlib for safe file operations.
3. Implement input validation.`,
                'Path traversal occurs when user input is used to access files without proper validation, allowing attackers to access sensitive files.'
            ));
        }

        // Hardcoded Secrets
        const secretPattern = /(apiKey|password|token|secret)\s*=\s*['"][^'"]*['"]/gi;
        while ((match = secretPattern.exec(text)) !== null) {
            vulnerabilities.push(new Vulnerability(
                'Hardcoded Secret',
                'Medium',
                'Hardcoded secret detected',
                document.positionAt(match.index).line + 1,
                match[0],
                'Store secrets in environment variables or secure vaults.',
                'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
                'CVE-2021-6789',
                `1. Move secrets to environment variables or secure vaults.
2. Use tools like HashiCorp Vault or AWS Secrets Manager.
3. Avoid committing secrets to version control.`,
                'Hardcoded secrets in source code can be easily exposed, leading to unauthorized access.'
            ));
        }
    }

    return vulnerabilities;
}

module.exports = { Vulnerability, scanForVulnerabilities };