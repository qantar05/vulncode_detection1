const vscode = require('vscode');

class Vulnerability {
    constructor(type, severity, message, line, codeSnippet, fix, documentation, cve, detailedSolution, context, autoFix = null) {
        this.type = type;
        this.severity = severity;
        this.message = message;
        this.line = line;
        this.codeSnippet = codeSnippet;
        this.fix = fix;
        this.documentation = documentation;
        this.cve = cve;
        this.detailedSolution = detailedSolution;
        this.context = context;
        this.autoFix = autoFix;
    }
}

function scanForVulnerabilities(document) {
    const vulnerabilities = [];
    const text = document.getText();
    const language = document.languageId;

    // Java Vulnerabilities
    if (language === 'java') {
        detectJavaVulnerabilities(text, document, vulnerabilities);
    }
    // JavaScript Vulnerabilities
    else if (language === 'javascript') {
        detectJavaScriptVulnerabilities(text, document, vulnerabilities);
    }
    // Python Vulnerabilities
    else if (language === 'python') {
        detectPythonVulnerabilities(text, document, vulnerabilities);
    }

    // Calculate risk score based on vulnerabilities
    const riskScore = calculateRiskScore(vulnerabilities);

    return {
        vulnerabilities,
        riskScore
    };
}

function calculateRiskScore(vulnerabilities) {
    const severityWeights = {
        'Critical': 10,
        'High': 7,
        'Medium': 4,
        'Low': 1
    };

    let score = 0;
    vulnerabilities.forEach(vuln => {
        score += severityWeights[vuln.severity] || 0;
    });

    // Cap the score at 100
    return Math.min(score * 5, 100);
}

// ==================== Java Vulnerability Detectors ====================

function detectJavaVulnerabilities(text, document, vulnerabilities) {
    let match;

    // 1. SQL Injection
    const sqlInjectionPattern = /(?:Statement|executeQuery|executeUpdate)\s*\([^)]*['"][^'"]*['"]/gi;
    while ((match = sqlInjectionPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'SQL Injection',
            'High',
            'Concatenated SQL query detected',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use PreparedStatement with parameterized queries',
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'CVE-2021-1234',
            `1. Replace with: PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
2. Use stmt.setString(1, userInput) for parameters`,
            'Attackers can inject malicious SQL through unparameterized inputs',
            {
                pattern: /(['"]).*?\1/,
                replacement: '?'
            }
        ));
    }

    // 2. Cross-Site Scripting (XSS)
    const xssPattern = /(?:response\.getWriter\(\)\.write|print(?:ln)?)\s*\([^)]*['"][^'"]*['"]/gi;
    while ((match = xssPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Cross-Site Scripting (XSS)',
            'High',
            'Unsanitized output to HTTP response',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use OWASP Java Encoder or HTML escaping',
            'https://owasp.org/www-community/attacks/xss/',
            'CVE-2021-2345',
            `1. Add: import org.owasp.encoder.Encode;
2. Replace with: response.getWriter().write(Encode.forHtml(userInput))`,
            'Attackers can inject malicious scripts into web pages'
        ));
    }

    // 3. Insecure Deserialization
    const deserializationPattern = /(?:ObjectInputStream|readObject|readUnshared)\s*\([^)]*\)/gi;
    while ((match = deserializationPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Insecure Deserialization',
            'Critical',
            'Raw deserialization of objects detected',
            document.positionAt(match.index).line + 1,
            match[0],
            'Implement validateObject() or use safe formats like JSON',
            'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
            'CVE-2021-3456',
            `1. Add: inputStream.setObjectInputFilter(new CustomFilter());
2. Or migrate to JSON parsers like Jackson`,
            'Attackers can craft malicious serialized objects to execute code'
        ));
    }

    // 4. Path Traversal
    const pathTraversalPattern = /(?:FileInputStream|FileReader|Files\.readAllLines)\s*\([^)]*['"][^/"]*\.\./gi;
    while ((match = pathTraversalPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Path Traversal',
            'High',
            'Unvalidated file path with ../ sequences',
            document.positionAt(match.index).line + 1,
            match[0],
            'Validate paths against whitelist',
            'https://owasp.org/www-community/attacks/Path_Traversal',
            'CVE-2021-4567',
            `1. Use: Path path = Paths.get(baseDir).normalize().resolve(userInput);
2. Verify: if (!path.startsWith(baseDir)) throw new SecurityException();`,
            'Attackers can access files outside intended directory'
        ));
    }

    // 5. Hardcoded Secrets
    const secretPattern = /(?:password|apiKey|secret|token)\s*=\s*["'][^"']{10,}["']/gi;
    while ((match = secretPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Hardcoded Secret',
            'Medium',
            'Sensitive credential stored in code',
            document.positionAt(match.index).line + 1,
            match[0],
            'Move to environment variables or secure vault',
            'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
            'CVE-2021-5678',
            `1. Remove from code
2. Use: String password = System.getenv("DB_PASSWORD");
3. Store in AWS Secrets Manager or similar`,
            'Credentials can be extracted from compiled binaries'
        ));
    }

    // 6. Command Injection
    const commandInjectionPattern = /Runtime\.getRuntime\(\).exec\s*\([^)]*['"][^'"]*['"]/gi;
    while ((match = commandInjectionPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Command Injection',
            'Critical',
            'Unsanitized input in system command',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use ProcessBuilder with argument list',
            'https://owasp.org/www-community/attacks/Command_Injection',
            'CVE-2021-6789',
            `1. Replace with:
ProcessBuilder pb = new ProcessBuilder("ls", "-l", sanitizedInput);
Process p = pb.start();`,
            'Attackers can chain commands with ; or | characters'
        ));
    }

    // 7. Insecure Randomness
    const randomPattern = /new Random\s*\(|Math\.random\s*\(/gi;
    while ((match = randomPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Insecure Randomness',
            'Medium',
            'Predictable random number generator',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use SecureRandom for cryptographic operations',
            'https://owasp.org/www-community/vulnerabilities/Insecure_Randomness',
            'CVE-2021-7890',
            `1. Replace with: SecureRandom random = new SecureRandom();
2. For non-crypto: ThreadLocalRandom.current().nextInt()`,
            'Predictable values can compromise security mechanisms'
        ));
    }

    // 8. XML External Entity (XXE) Injection
    const xxePattern = /(?:DocumentBuilderFactory|SAXParserFactory)\s*\.newInstance\s*\([^)]*\)[^;]*setFeature\s*\([^)]*false\s*\)/gi;
    while ((match = xxePattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'XXE Injection',
            'High',
            'XML parser with external entities enabled',
            document.positionAt(match.index).line + 1,
            match[0],
            'Disable DTD and external entities',
            'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
            'CVE-2021-8901',
            `1. Add before parsing:
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);`,
            'Attackers can read local files or make network requests'
        ));
    }

    // 9. Log Injection
    const logInjectionPattern = /(?:LOGGER|logger|log)\.(?:info|error|debug)\s*\([^)]*['"][^'"]*['"]/gi;
    while ((match = logInjectionPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Log Injection',
            'Medium',
            'Unsanitized input in log statements',
            document.positionAt(match.index).line + 1,
            match[0],
            'Sanitize or redact sensitive data',
            'https://owasp.org/www-community/attacks/Log_Injection',
            'CVE-2021-9012',
            `1. Use: LOGGER.info("User: {}", sanitize(userInput));
2. Implement custom log sanitizer`,
            'Attackers can forge log entries or leak sensitive data'
        ));
    }
}

// ==================== JavaScript Vulnerability Detectors ====================

function detectJavaScriptVulnerabilities(text, document, vulnerabilities) {
    let match;

    // 1. Prototype Pollution
    const prototypePollutionPattern = /(?:Object\.assign|merge|extend)\s*\([^)]*['"](?:__proto__|constructor|prototype)/gi;
    while ((match = prototypePollutionPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Prototype Pollution',
            'High',
            'Dangerous object property merge',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use Object.create(null) for safe objects',
            'https://owasp.org/www-community/attacks/Prototype_Pollution',
            'CVE-2021-2345',
            `1. Replace with: const safeMerge = (target, ...sources) => {
   sources.forEach(source => {
       Object.keys(source).forEach(key => {
           if (key !== '__proto__') {
               target[key] = source[key];
           }
       });
   });
}`,
            'Attackers can modify object prototypes to change application behavior'
        ));
    }

    // 2. Insecure Use of eval()
    const evalPattern = /\beval\s*\(|new Function\s*\(/gi;
    while ((match = evalPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Insecure eval()',
            'Critical',
            'Dynamic code execution detected',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use JSON.parse() or safe alternatives',
            'https://owasp.org/www-community/attacks/Code_Injection',
            'CVE-2021-3456',
            `1. For JSON: JSON.parse(userInput)
2. For math: mathjs.evaluate(userInput)
3. For templates: Handlebars.compile(template)`,
            'Attackers can execute arbitrary JavaScript code'
        ));
    }

    // 3. Insecure LocalStorage Usage
    const localStoragePattern = /localStorage\.(setItem|getItem)\s*\([^)]*['"](password|token|secret)/gi;
    while ((match = localStoragePattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Insecure localStorage',
            'Medium',
            'Sensitive data in browser storage',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use secure HTTP-only cookies',
            'https://owasp.org/www-community/vulnerabilities/Insecure_Storage',
            'CVE-2021-4567',
            `1. For sessions: Use httpOnly cookies
2. For tokens: Use secure, sameSite cookies
3. Encrypt before storage if required`,
            'Data can be stolen via XSS or directly from browser'
        ));
    }

    // 4. NoSQL Injection
    const nosqlPattern = /(?:db\.collection|find|update)\s*\([^)]*['"][^'"]*['"]\s*\)/gi;
    while ((match = nosqlPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'NoSQL Injection',
            'High',
            'Unsanitized input in database query',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use parameterized queries or schema validation',
            'https://owasp.org/www-community/attacks/NoSQL_Injection',
            'CVE-2021-5678',
            `1. For MongoDB: 
db.collection.find({ $eq: userInput })
2. Validate with Joi or similar`,
            'Attackers can modify query logic with JSON operators'
        ));
    }

    // 5. Cross-Site Request Forgery (CSRF)
    const csrfPattern = /fetch\s*\([^)]*['"](POST|PUT|DELETE)[^'"]*['"][^)]*{.*credentials:\s*['"]include['"]/gi;
    while ((match = csrfPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'CSRF Vulnerability',
            'Medium',
            'Missing CSRF protection',
            document.positionAt(match.index).line + 1,
            match[0],
            'Add CSRF tokens and same-site cookies',
            'https://owasp.org/www-community/attacks/csrf',
            'CVE-2021-6789',
            `1. Add: <meta name="csrf-token" content="{{csrfToken}}">
2. Configure: 
fetch(url, {
    headers: { 'X-CSRF-Token': getCSRFToken() }
})`,
            'Attackers can force users to execute unwanted actions'
        ));
    }
}

// ==================== Python Vulnerability Detectors ====================

function detectPythonVulnerabilities(text, document, vulnerabilities) {
    let match;

    // 1. SQL Injection
    const pySqlPattern = /(?:execute|executemany)\s*\([^)]*['"][^'"]*['"]\s*[),]/gi;
    while ((match = pySqlPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'SQL Injection',
            'High',
            'Concatenated SQL query in Python',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use parameterized queries',
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'CVE-2021-1234',
            `1. For SQLite: 
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
2. For PostgreSQL: 
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
            'Attackers can inject malicious SQL through string formatting'
        ));
    }

    // 2. Insecure Use of eval()
    const pyEvalPattern = /(?:eval|exec)\s*\([^)]*input\s*\(/gi;
    while ((match = pyEvalPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Insecure eval()',
            'Critical',
            'Dynamic code execution from user input',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use ast.literal_eval() for simple parsing',
            'https://owasp.org/www-community/attacks/Code_Injection',
            'CVE-2021-2345',
            `1. For math: Use eval only with whitelisted chars:
if set(user_input) <= set('0123456789+-*/.() '):
    eval(user_input)
2. For JSON: json.loads(user_input)`,
            'Attackers can execute arbitrary Python code'
        ));
    }

    // 3. Command Injection
    const pyCommandPattern = /(?:os\.system|subprocess\.(?:run|call|Popen))\s*\([^)]*['"][^'"]*['"]\s*[),]/gi;
    while ((match = pyCommandPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Command Injection',
            'Critical',
            'Unsanitized input in system command',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use subprocess with argument lists',
            'https://owasp.org/www-community/attacks/Command_Injection',
            'CVE-2021-3456',
            `1. Replace with:
subprocess.run(['ls', '-l', user_input], check=True)
2. Use shlex.quote() if string is required`,
            'Attackers can chain commands with ; or &&'
        ));
    }

    // 4. Insecure Deserialization
    const pyDeserializePattern = /(?:pickle|yaml)\.(?:load|loads)\s*\(/gi;
    while ((match = pyDeserializePattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Insecure Deserialization',
            'Critical',
            'Unsafe deserialization of data',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use JSON or implement allow lists',
            'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
            'CVE-2021-4567',
            `1. For simple data: json.loads(user_input)
2. If pickle is required:
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == '__main__' and name in safe_classes:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")`,
            'Attackers can execute arbitrary code during deserialization'
        ));
    }

    // 5. Path Traversal
    const pyPathPattern = /(?:open|Path)\s*\([^)]*['"][^/"]*\.\./gi;
    while ((match = pyPathPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Path Traversal',
            'High',
            'Unvalidated file path with ../',
            document.positionAt(match.index).line + 1,
            match[0],
            'Validate paths against base directory',
            'https://owasp.org/www-community/attacks/Path_Traversal',
            'CVE-2021-5678',
            `1. Use pathlib.Path with absolute checking:
from pathlib import Path
base = Path('/safe/dir')
user_path = Path(user_input)
if not user_path.resolve().is_relative_to(base):
    raise ValueError("Invalid path")`,
            'Attackers can access files outside intended directory'
        ));
    }

    // 6. Hardcoded Secrets
    const pySecretPattern = /(?:password|api_key|secret|token)\s*=\s*['"][^'"]{10,}['"]/gi;
    while ((match = pySecretPattern.exec(text)) !== null) {
        vulnerabilities.push(new Vulnerability(
            'Hardcoded Secret',
            'Medium',
            'Sensitive credential in source code',
            document.positionAt(match.index).line + 1,
            match[0],
            'Use environment variables',
            'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
            'CVE-2021-6789',
            `1. Move to environment:
import os
password = os.getenv('DB_PASSWORD')
2. Use python-dotenv for development`,
            'Credentials can be extracted from source or bytecode'
        ));
    }
}

module.exports = {
    Vulnerability,
    scanForVulnerabilities
};