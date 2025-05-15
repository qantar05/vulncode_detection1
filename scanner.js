const vscode = require('vscode');
const { OpenAI } = require('openai');
const ASTParser = require('./astParser');

// Configure OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || vscode.workspace.getConfiguration('vulnerabilityScanner').get('openaiApiKey'),
});

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
        this.aiAnalysis = '';
        this.attackScenario = '';
        this.testCases = [];
        this.cvssScore = null;
        this.poc = '';
    }

    async enrichWithAI() {
        if (vscode.workspace.getConfiguration('vulnerabilityScanner').get('enableAI')) {
            try {
                this.attackScenario = await this.generateAttackScenario();
                this.aiAnalysis = await this.generateAIExplanation();
                this.testCases = await this.generateTestCases();
                this.poc = await this.generateProofOfConcept();
                
                if (this.cve) {
                    this.cvssScore = await this.getCvssScore();
                }
            } catch (error) {
                console.error('AI enrichment error:', error);
            }
        }
    }

    async generateAttackScenario() {
        const prompt = `Generate a detailed attack scenario for a ${this.type} vulnerability. 
        Vulnerability details: ${this.message}
        Code context: ${this.codeSnippet}
        
        Provide:
        1. How an attacker could exploit this
        2. Potential impact
        3. Step-by-step exploitation process
        4. Real-world examples of similar exploits`;

        const response = await openai.chat.completions.create({
            model: "gpt-3.5-turbo",
            messages: [{
                role: "user",
                content: prompt
            }],
            max_tokens: 500,
            temperature: 0.7,
        });

        return response.choices[0].message.content.trim();
    }

    async generateAIExplanation() {
        const prompt = `Explain why this code is vulnerable to ${this.type}:
        Code: ${this.codeSnippet}
        Vulnerability: ${this.message}
        
        Provide:
        1. Technical explanation of the vulnerability
        2. Why the current implementation is insecure
        3. Security principles being violated`;

        const response = await openai.completions.create({
            model: "text-davinci-003",
            prompt: prompt,
            max_tokens: 300,
            temperature: 0.5,
        });

        return response.choices[0].text.trim();
    }

    async generateTestCases() {
        const prompt = `Generate 3 test cases to verify the presence of a ${this.type} vulnerability:
        Vulnerability: ${this.message}
        Code: ${this.codeSnippet}
        
        For each test case provide:
        1. Input to use
        2. Expected behavior if vulnerable
        3. Expected behavior if fixed`;

        const response = await openai.completions.create({
            model: "text-davinci-003",
            prompt: prompt,
            max_tokens: 400,
            temperature: 0.6,
        });

        const testCases = [];
        const lines = response.choices[0].text.trim().split('\n');
        let currentCase = {};
        
        for (const line of lines) {
            if (line.match(/Test Case \d:/i)) {
                if (Object.keys(currentCase).length > 0) {
                    testCases.push(currentCase);
                }
                currentCase = { 
                    name: line.trim(),
                    input: '',
                    vulnerableBehavior: '',
                    fixedBehavior: ''
                };
            } else if (line.match(/Input:/i)) {
                currentCase.input = line.replace(/Input:/i, '').trim();
            } else if (line.match(/Vulnerable Behavior:/i)) {
                currentCase.vulnerableBehavior = line.replace(/Vulnerable Behavior:/i, '').trim();
            } else if (line.match(/Fixed Behavior:/i)) {
                currentCase.fixedBehavior = line.replace(/Fixed Behavior:/i, '').trim();
            }
        }
        
        if (Object.keys(currentCase).length > 0) {
            testCases.push(currentCase);
        }
        
        return testCases;
    }

    async generateProofOfConcept() {
        const prompt = `Generate a safe proof-of-concept exploit for a ${this.type} vulnerability.
        Vulnerability details: ${this.message}
        Code context: ${this.codeSnippet}
        
        Provide:
        1. A working exploit code snippet
        2. Explanation of how it works
        3. Expected output when successful
        4. Safety precautions for testing`;

        const response = await openai.completions.create({
            model: "text-davinci-003",
            prompt: prompt,
            max_tokens: 600,
            temperature: 0.7,
        });

        return response.choices[0].text.trim();
    }

    async getCvssScore() {
        try {
            // This would typically call an API like NVD or a vulnerability database
            // For now, we'll simulate it with AI
            const prompt = `Estimate a CVSS score (0-10) for a ${this.type} vulnerability:
            Description: ${this.message}
            CVE: ${this.cve}
            
            Provide just the numerical score (e.g., 7.5)`;

            const response = await openai.completions.create({
                model: "text-davinci-003",
                prompt: prompt,
                max_tokens: 10,
                temperature: 0.3,
            });

            return parseFloat(response.choices[0].text.trim());
        } catch (error) {
            console.error('CVSS score estimation error:', error);
            return null;
        }
    }
}

async function scanForVulnerabilities(document) {
    const vulnerabilities = [];
    const text = document.getText();
    const language = document.languageId;

    // First use AST parsing for more accurate detection
    if (language === 'javascript' || language === 'typescript') {
        const astVulnerabilities = await ASTParser.parseJavaScript(text, document);
        vulnerabilities.push(...astVulnerabilities);
    }

    // Then use regex patterns as fallback
    if (language === 'java') {
        detectJavaVulnerabilities(text, document, vulnerabilities);
    } else if (language === 'javascript' || language === 'typescript') {
        detectJavaScriptVulnerabilities(text, document, vulnerabilities);
    } else if (language === 'python') {
        detectPythonVulnerabilities(text, document, vulnerabilities);
    }

    // Enrich vulnerabilities with AI analysis
    if (vscode.workspace.getConfiguration('vulnerabilityScanner').get('enableAI')) {
        await Promise.all(vulnerabilities.map(async vuln => {
            await vuln.enrichWithAI();
        }));
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

    let score = vulnerabilities.reduce((sum, vuln) => {
        return sum + (severityWeights[vuln.severity] || 0) * (vuln.cvssScore || 1);
    }, 0);

    // Normalize to 0-100 scale
    return Math.min(Math.round(score * 100 / (vulnerabilities.length * 10 || 1)), 100);
}

// ==================== Java Vulnerability Detectors ====================
function detectJavaVulnerabilities(text, document, vulnerabilities) {
    let match;

    // SQL Injection
    const sqlInjectionPattern = /(?:Statement|executeQuery|executeUpdate)\s*\([^)]*['"][^'"]*['"]/gi;
    while ((match = sqlInjectionPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);
        
        vulnerabilities.push(new Vulnerability(
            'SQL Injection',
            'High',
            'Concatenated SQL query detected',
            line,
            codeSnippet,
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

    // XSS
    const xssPattern = /(?:response\.getWriter\(\)\.write|print(?:ln)?)\s*\([^)]*['"][^'"]*['"]/gi;
    while ((match = xssPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);
        
        vulnerabilities.push(new Vulnerability(
            'Cross-Site Scripting (XSS)',
            'High',
            'Unsanitized output to HTTP response',
            line,
            codeSnippet,
            'Use OWASP Java Encoder or HTML escaping',
            'https://owasp.org/www-community/attacks/xss/',
            'CVE-2021-2345',
            `1. Add: import org.owasp.encoder.Encode;
2. Replace with: response.getWriter().write(Encode.forHtml(userInput))`,
            'Attackers can inject malicious scripts into web pages'
        ));
    }

    // Insecure Deserialization
    const deserializationPattern = /(?:ObjectInputStream|readObject|readUnshared)\s*\([^)]*\)/gi;
    while ((match = deserializationPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);
        
        vulnerabilities.push(new Vulnerability(
            'Insecure Deserialization',
            'Critical',
            'Raw deserialization of objects detected',
            line,
            codeSnippet,
            'Implement validateObject() or use safe formats like JSON',
            'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
            'CVE-2021-3456',
            `1. Add: inputStream.setObjectInputFilter(new CustomFilter());
2. Or migrate to JSON parsers like Jackson`,
            'Attackers can craft malicious serialized objects to execute code'
        ));
    }
}

// ==================== JavaScript Vulnerability Detectors ====================
function detectJavaScriptVulnerabilities(text, document, vulnerabilities) {
    let match;

    // Prototype Pollution
    const prototypePollutionPattern = /(?:Object\.assign|merge|extend)\s*\([^)]*['"](?:__proto__|constructor|prototype)/gi;
    while ((match = prototypePollutionPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);
        
        vulnerabilities.push(new Vulnerability(
            'Prototype Pollution',
            'High',
            'Dangerous object property merge',
            line,
            codeSnippet,
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

    // Insecure eval()
    const evalPattern = /\beval\s*\(|new Function\s*\(/gi;
    while ((match = evalPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);
        
        vulnerabilities.push(new Vulnerability(
            'Insecure eval()',
            'Critical',
            'Dynamic code execution detected',
            line,
            codeSnippet,
            'Use JSON.parse() or safe alternatives',
            'https://owasp.org/www-community/attacks/Code_Injection',
            'CVE-2021-3456',
            `1. For JSON: JSON.parse(userInput)
2. For math: mathjs.evaluate(userInput)
3. For templates: Handlebars.compile(template)`,
            'Attackers can execute arbitrary JavaScript code'
        ));
    }
}

// ==================== Python Vulnerability Detectors ====================
function detectPythonVulnerabilities(text, document, vulnerabilities) {
    let match;

    // SQL Injection
    const pySqlPattern = /(?:execute|executemany)\s*\([^)]*['"][^'"]*['"]\s*[),]/gi;
    while ((match = pySqlPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);
        
        vulnerabilities.push(new Vulnerability(
            'SQL Injection',
            'High',
            'Concatenated SQL query in Python',
            line,
            codeSnippet,
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

    // Insecure eval()
    const pyEvalPattern = /(?:eval|exec)\s*\([^)]*input\s*\(/gi;
    while ((match = pyEvalPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);
        
        vulnerabilities.push(new Vulnerability(
            'Insecure eval()',
            'Critical',
            'Dynamic code execution from user input',
            line,
            codeSnippet,
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
}

// Helper function to get code snippet around a line
function getCodeSnippet(text, lineNumber, contextLines = 3) {
    const lines = text.split('\n');
    const start = Math.max(0, lineNumber - 1 - contextLines);
    const end = Math.min(lines.length, lineNumber - 1 + contextLines + 1);
    return lines.slice(start, end).join('\n');
}

module.exports = {
    Vulnerability,
    scanForVulnerabilities
};