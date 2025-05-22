const vscode = require('vscode');
const ASTParser = require('./astParser');
const cweApi = require('./cweApi');

class Vulnerability {
    /**
     * Create a new vulnerability
     * @param {string|null} type - Vulnerability type (can be populated from CWE API)
     * @param {string|null} severity - Severity level (can be populated from CWE API)
     * @param {string} message - Brief description of the vulnerability
     * @param {number} line - Line number where the vulnerability was found
     * @param {string} codeSnippet - Code snippet containing the vulnerability
     * @param {string|null} fix - Brief fix recommendation (can be populated from CWE API)
     * @param {string|null} documentation - Documentation URL (can be populated from CWE API)
     * @param {string|null} cve - CVE identifier
     * @param {string|null} detailedSolution - Detailed fix recommendation (can be populated from CWE API)
     * @param {string|null} context - Additional context (can be populated from CWE API)
     * @param {object|null} autoFix - Auto-fix information
     * @param {number|null} cweId - CWE identifier (essential for CWE API integration)
     */
    constructor(type, severity, message, line, codeSnippet, fix = null, documentation = null, cve = null, detailedSolution = null, context = null, autoFix = null, cweId = null) {
        // Required fields
        this.line = line;
        this.codeSnippet = codeSnippet;
        this.message = message || 'Potential security vulnerability detected';

        // Fields that can be populated from CWE API
        this.type = type || null;
        this.severity = severity || 'Medium';  // Default severity
        this.fix = fix || null;
        this.documentation = documentation || null;
        this.detailedSolution = detailedSolution || null;
        this.context = context || null;

        // Other fields
        this.cve = cve || null;
        this.autoFix = autoFix || null;
        this.cweId = cweId || null;

        // Fields for AI enrichment
        this.aiAnalysis = '';
        this.attackScenario = '';
        this.testCases = [];
        this.cvssScore = null;
        this.poc = '';
        this.cweInfo = null;
    }

    async enrichWithAI() {
        // Check if AI features are enabled
        if (vscode.workspace.getConfiguration('vulnerabilityScanner').get('enableAI')) {
            try {
                // Generate attack scenario and proof of concept
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

        // Fetch CWE information if available (independent of AI features)
        if (this.cweId && vscode.workspace.getConfiguration('vulnerabilityScanner').get('enableCWEApi', true)) {
            try {
                await this.fetchCWEInfo();
            } catch (error) {
                console.error('CWE info fetch error:', error);
            }
        }
    }

    /**
     * Fetch CWE information from the CWE REST API and populate vulnerability fields
     * @returns {Promise<void>}
     */
    async fetchCWEInfo() {
        if (!this.cweId) return;

        try {
            this.cweInfo = await cweApi.getSimplifiedCWEInfo(this.cweId);

            // Enhanced debug logging to understand the CWE data structure
            console.log(`CWE-${this.cweId} info received:`, {
                name: this.cweInfo?.name,
                description: this.cweInfo?.description?.substring(0, 50) + '...',
                mitigationsCount: this.cweInfo?.mitigations?.length || 0,
                consequencesCount: this.cweInfo?.consequences?.length || 0,
                mitigationsExample: this.cweInfo?.mitigations?.[0] ?
                    (typeof this.cweInfo.mitigations[0] === 'string' ?
                        this.cweInfo.mitigations[0].substring(0, 50) + '...' :
                        JSON.stringify(this.cweInfo.mitigations[0]).substring(0, 50) + '...') :
                    'none'
            });

            // Log the full mitigations array for debugging
            if (this.cweInfo?.mitigations) {
                console.log(`CWE-${this.cweId} mitigations:`, JSON.stringify(this.cweInfo.mitigations, null, 2));
            } else {
                console.log(`CWE-${this.cweId} has no mitigations data`);
            }

            if (this.cweInfo) {
                // Set type if not already set or if it's a generic name
                if (!this.type || this.type.includes('Vulnerability')) {
                    this.type = this.cweInfo.name || `CWE-${this.cweId} Vulnerability`;
                }

                // Update documentation link
                if (this.cweInfo.url) {
                    this.documentation = this.cweInfo.url;
                    this.cweDocumentation = this.cweInfo.url;
                }

                // Update severity if not already set or if set to default
                if ((!this.severity || this.severity === 'Medium') && this.cweInfo.severity) {
                    this.severity = this.cweInfo.severity;
                }

                // Set description/context if not already set
                if (!this.context || this.context.length < 50) {
                    this.context = this.cweInfo.description || this.context;
                }

                // Set fix recommendation if not already set
                if (!this.fix || this.fix.length < 20) {
                    // Extract mitigation advice from CWE
                    if (this.cweInfo.mitigations && Array.isArray(this.cweInfo.mitigations) && this.cweInfo.mitigations.length > 0) {
                        const mitigations = this.cweInfo.mitigations.map(m => {
                            if (typeof m === 'string') return m;
                            if (m && typeof m === 'object' && m.Description) return m.Description;
                            return '';
                        }).filter(m => m).join('\n');

                        if (mitigations) {
                            this.fix = mitigations;

                            // Always update detailed solution with mitigations
                            this.detailedSolution = mitigations;

                            console.log(`Set fix and detailedSolution for CWE-${this.cweId}:`, {
                                fixLength: this.fix?.length || 0,
                                detailedSolutionLength: this.detailedSolution?.length || 0
                            });
                        } else {
                            console.log(`No mitigations text could be extracted for CWE-${this.cweId}`);
                        }
                    } else {
                        console.log(`No valid mitigations array for CWE-${this.cweId}`);
                    }
                } else {
                    console.log(`Fix already set for CWE-${this.cweId}, length: ${this.fix?.length || 0}`);
                }

                // Enhance message with CWE information if it's generic
                if (this.message && this.message.length < 30 && this.cweInfo.description) {
                    this.message = `${this.message} (${this.cweInfo.description.substring(0, 100)}${this.cweInfo.description.length > 100 ? '...' : ''})`;
                }
            }
        } catch (error) {
            console.error(`Error fetching CWE-${this.cweId} information:`, error);
        }
    }

    async generateAttackScenario() {
        // Use the AttackSimulator instead of direct OpenAI calls
        const AttackSimulator = require('./attackSimulator');
        try {
            // We'll reuse the generateProofOfConcept method since it provides similar information
            return await AttackSimulator.generateProofOfConcept(this);
        } catch (error) {
            console.error('Error generating attack scenario:', error);
            return "Could not generate attack scenario due to an error.";
        }
    }

    async generateAIExplanation() {
        // Use the AttackSimulator instead of direct OpenAI calls
        const AttackSimulator = require('./attackSimulator');
        try {
            // We'll reuse the generateProofOfConcept method but modify the prompt
            // This is a simplified approach - in a real implementation, you might want to add a specific method
            return await AttackSimulator.generateProofOfConcept(this);
        } catch (error) {
            console.error('Error generating AI explanation:', error);
            return "Could not generate explanation due to an error.";
        }
    }

    async generateTestCases() {
        // Return a simple test case since we're focusing on the Attack Simulator functionality
        return [{
            name: "Test Case 1",
            input: "Use the Attack Simulator button for detailed vulnerability analysis.",
            vulnerableBehavior: "The vulnerability would be exploitable.",
            fixedBehavior: "The vulnerability would be mitigated."
        }];
    }

    async generateProofOfConcept() {
        // Use the AttackSimulator instead of direct OpenAI calls
        const AttackSimulator = require('./attackSimulator');
        try {
            return await AttackSimulator.generateProofOfConcept(this);
        } catch (error) {
            console.error('Error generating proof of concept:', error);
            return "Could not generate proof of concept due to an error.";
        }
    }

    async getCvssScore() {
        // Return a default score based on severity
        const severityScores = {
            'Critical': 9.5,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5
        };
        return severityScores[this.severity] || 5.0;
    }
}

async function scanForVulnerabilities(document) {
    try {
        const vulnerabilities = [];
        const text = document.getText();
        const language = document.languageId;

        console.log(`Scanning document: ${document.fileName}, language: ${language}`);

        // First use AST parsing for more accurate detection
        if (language === 'javascript' || language === 'typescript') {
            try {
                const astVulnerabilities = await ASTParser.parseJavaScript(text, document);
                if (Array.isArray(astVulnerabilities)) {
                    vulnerabilities.push(...astVulnerabilities);
                }
            } catch (error) {
                console.error('Error in AST parsing:', error);
            }
        }

        // Then use regex patterns as fallback
        try {
            if (language === 'java') {
                detectJavaVulnerabilities(text, document, vulnerabilities);
            } else if (language === 'javascript' || language === 'typescript') {
                detectJavaScriptVulnerabilities(text, document, vulnerabilities);
            } else if (language === 'python') {
                detectPythonVulnerabilities(text, document, vulnerabilities);
            }
        } catch (error) {
            console.error('Error in regex pattern detection:', error);
        }

        // Enrich vulnerabilities with information
        await Promise.all(vulnerabilities.map(async vuln => {
            try {
                await vuln.enrichWithAI();
            } catch (error) {
                console.error('Error enriching vulnerability:', error);
            }
        }));

        // Calculate risk score based on vulnerabilities
        const riskScore = calculateRiskScore(vulnerabilities);

        console.log(`Scan completed. Found ${vulnerabilities.length} vulnerabilities.`);

        return {
            vulnerabilities,
            riskScore
        };
    } catch (error) {
        console.error('Error in vulnerability scanning:', error);
        return {
            vulnerabilities: [],
            riskScore: 0,
            error: error.message
        };
    }
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

    // SQL Injection (CWE-89)
    const sqlInjectionPattern = /(?:Statement|executeQuery|executeUpdate)\s*\([^)]*['"][^'"]*['"]/gi;
    while ((match = sqlInjectionPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential SQL injection vulnerability detected',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            {
                pattern: /(['"]).*?\1/,
                replacement: '?'
            },
            89 // CWE-89: Improper Neutralization of Special Elements used in an SQL Command
        ));
    }

    // XSS (CWE-79)
    const xssPattern = /(?:response\.getWriter\(\)\.write|print(?:ln)?)\s*\([^)]*['"][^'"]*['"]/gi;
    while ((match = xssPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential Cross-Site Scripting (XSS) vulnerability detected',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            79 // CWE-79: Improper Neutralization of Input During Web Page Generation
        ));
    }

    // Insecure Deserialization (CWE-502)
    const deserializationPattern = /(?:ObjectInputStream|readObject|readUnshared)\s*\([^)]*\)/gi;
    while ((match = deserializationPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential insecure deserialization vulnerability detected',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            502 // CWE-502: Deserialization of Untrusted Data
        ));
    }
}

// ==================== JavaScript Vulnerability Detectors ====================
function detectJavaScriptVulnerabilities(text, document, vulnerabilities) {
    let match;

    // Prototype Pollution (CWE-1321)
    const prototypePollutionPattern = /(?:Object\.assign|merge|extend)\s*\([^)]*['"](?:__proto__|constructor|prototype)/gi;
    while ((match = prototypePollutionPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential prototype pollution vulnerability detected',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            1321 // CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
        ));
    }

    // Insecure eval() (CWE-95)
    const evalPattern = /\beval\s*\(|new Function\s*\(|setTimeout\s*\(\s*['"][^'"]*['"]/gi;
    while ((match = evalPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential code injection vulnerability detected',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            95 // CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
        ));
    }

    // Hard-coded Credentials (CWE-259/CWE-798)
    const hardcodedCredentialsPattern = /(?:const|let|var)\s+(?:\w+(?:password|passwd|pwd|secret|key|token|credential|auth))\s*=\s*['"][^'"]+['"]/gi;
    while ((match = hardcodedCredentialsPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Hard-coded credentials detected',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            798 // CWE-798: Use of Hard-coded Credentials
        ));
    }

    // Weak Cryptography (CWE-327)
    const weakCryptoPattern = /crypto\.createCipher\s*\(\s*['"](?:des|rc4|md5)['"]/gi;
    while ((match = weakCryptoPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Use of weak cryptographic algorithm detected',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            327 // CWE-327: Use of a Broken or Risky Cryptographic Algorithm
        ));
    }

    // CSRF (CWE-352)
    const csrfPattern = /app\.(?:post|put|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*\([^)]*\)\s*=>/gi;
    while ((match = csrfPattern.exec(text)) !== null) {
        // Check if there's no CSRF token validation in the following lines
        const nextLines = text.substring(match.index, match.index + 200);
        if (!nextLines.match(/csrf|xsrf|token|nonce/i)) {
            const line = document.positionAt(match.index).line + 1;
            const codeSnippet = getCodeSnippet(text, line);

            vulnerabilities.push(new Vulnerability(
                null, // Will be populated from CWE API
                null, // Will be populated from CWE API
                'Potential CSRF vulnerability detected',
                line,
                codeSnippet,
                null, // Will be populated from CWE API
                null, // Will be populated from CWE API
                null,
                null, // Will be populated from CWE API
                null, // Will be populated from CWE API
                null,
                352 // CWE-352: Cross-Site Request Forgery (CSRF)
            ));
        }
    }

    // Path Traversal (CWE-22)
    const pathTraversalPattern = /(?:fs|require\(['"]fs['"]\))\.(?:readFileSync|readFile|writeFileSync|writeFile|appendFileSync|appendFile|createReadStream|createWriteStream)\s*\(\s*(?:[^)]*\+\s*|`[^`]*\$\{)[^)]*\)/gi;
    while ((match = pathTraversalPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential path traversal vulnerability detected',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            22 // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
        ));
    }

    // SSRF (CWE-918)
    const ssrfPattern = /(?:fetch|axios|http\.get|https\.get|request|superagent)\s*\(\s*(?:[^)]*\+\s*|`[^`]*\$\{|req\.(?:query|params|body)\.)[^)]*\)/gi;
    while ((match = ssrfPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential Server-Side Request Forgery (SSRF) vulnerability detected',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            918 // CWE-918: Server-Side Request Forgery (SSRF)
        ));
    }

    // Alternative SSRF pattern - direct use of user input in URL
    const directUrlPattern = /(?:function|const|let|var)\s+\w+\s*\([^)]*\)\s*\{[^}]*(?:fetch|axios|http\.get|https\.get|request)\s*\(\s*(?:url|req\.query\.url)/gi;
    while ((match = directUrlPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential Server-Side Request Forgery (SSRF) vulnerability detected',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            918 // CWE-918: Server-Side Request Forgery (SSRF)
        ));
    }

    // Weak Randomness (CWE-330)
    const weakRandomnessPattern = /Math\.random\s*\(\s*\)/gi;
    while ((match = weakRandomnessPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Use of cryptographically weak random number generator',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            330 // CWE-330: Use of Insufficiently Random Values
        ));
    }

    // Unrestricted File Upload (CWE-434)
    const unrestrictionUploadPattern = /(?:\.mv\s*\(|multer|formidable|busboy|multiparty|file\.mv|req\.files)/gi;
    while ((match = unrestrictionUploadPattern.exec(text)) !== null) {
        // Check if there's no file type validation in the following lines
        const nextLines = text.substring(match.index, match.index + 200);
        if (!nextLines.match(/(?:filetype|mimetype|extension).*check|\.(?:endsWith|match)\s*\(\s*['"]\.(?:jpg|png|pdf)/i)) {
            const line = document.positionAt(match.index).line + 1;
            const codeSnippet = getCodeSnippet(text, line);

            vulnerabilities.push(new Vulnerability(
                null, // Will be populated from CWE API
                null, // Will be populated from CWE API
                'Potential unrestricted file upload vulnerability detected',
                line,
                codeSnippet,
                null, // Will be populated from CWE API
                null, // Will be populated from CWE API
                null,
                null, // Will be populated from CWE API
                null, // Will be populated from CWE API
                null,
                434 // CWE-434: Unrestricted Upload of File with Dangerous Type
            ));
        }
    }

    // Integer Overflow (CWE-190)
    const integerOverflowPattern = /(?:(?:var|let|const)\s+\w+\s*=\s*\d+|[\w.]+\s*\+=\s*[\w.]+)(?![\s\S]*(?:if\s*\(\s*[\w.]+\s*(?:>|<|>=|<=)\s*(?:Number\.MAX_SAFE_INTEGER|Number\.MIN_SAFE_INTEGER|\d+)\s*\)))/gi;
    while ((match = integerOverflowPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential integer overflow vulnerability detected',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            190 // CWE-190: Integer Overflow or Wraparound
        ));
    }

    // Missing Encryption (CWE-311)
    const missingEncryptionPattern = /(?:localStorage\.setItem|sessionStorage\.setItem)\s*\(\s*['"][^'"]*(?:password|token|secret|key|auth|credential|ssn|dob|credit|card|social|security|personal|private|sensitive)['"]/gi;
    while ((match = missingEncryptionPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Sensitive data stored without encryption',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            311 // CWE-311: Missing Encryption of Sensitive Data
        ));
    }

    // Alternative pattern for missing encryption - JSON.stringify of sensitive data
    const jsonStringifyPattern = /JSON\.stringify\s*\(\s*\{[^}]*(?:ssn|dob|credit|card|social|security|personal|private|sensitive)[^}]*\}\s*\)/gi;
    while ((match = jsonStringifyPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Sensitive data stored without encryption',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            311 // CWE-311: Missing Encryption of Sensitive Data
        ));
    }
}

// ==================== Python Vulnerability Detectors ====================
function detectPythonVulnerabilities(text, document, vulnerabilities) {
    let match;

    // SQL Injection (CWE-89)
    const pySqlPattern = /(?:execute|executemany)\s*\([^)]*['"][^'"]*['"]\s*[),]/gi;
    while ((match = pySqlPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential SQL injection vulnerability detected in Python code',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            89 // CWE-89: Improper Neutralization of Special Elements used in an SQL Command
        ));
    }

    // Insecure eval() (CWE-95)
    const pyEvalPattern = /(?:eval|exec)\s*\([^)]*input\s*\(/gi;
    while ((match = pyEvalPattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential code injection vulnerability detected in Python code',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            95 // CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
        ));
    }

    // Pickle Deserialization (CWE-502)
    const picklePattern = /pickle\.(?:loads|load)\s*\(/gi;
    while ((match = picklePattern.exec(text)) !== null) {
        const line = document.positionAt(match.index).line + 1;
        const codeSnippet = getCodeSnippet(text, line);

        vulnerabilities.push(new Vulnerability(
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            'Potential insecure deserialization vulnerability detected in Python code',
            line,
            codeSnippet,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            null, // Will be populated from CWE API
            null, // Will be populated from CWE API
            null,
            502 // CWE-502: Deserialization of Untrusted Data
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