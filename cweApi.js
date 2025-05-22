/**
 * CWE REST API Client
 *
 * This module provides a client for interacting with the Common Weakness Enumeration (CWE) REST API.
 * It allows retrieving CWE information by ID, type, and relationships.
 *
 * API Base URL: https://cwe-api.mitre.org/api/v1/
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');

// Try to load vscode module, but make it optional for testing
let vscode = null;
try {
    vscode = require('vscode');
} catch (error) {
    console.log('vscode module not available, running in test mode');
}

class CWEApiClient {
    constructor() {
        this.BASE_URL = 'https://cwe-api.mitre.org/api/v1';
        this.CACHE_DIR = path.join(__dirname, '.cwe_cache');
        this.CACHE_EXPIRY = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds

        // Create cache directory if it doesn't exist
        if (!fs.existsSync(this.CACHE_DIR)) {
            try {
                fs.mkdirSync(this.CACHE_DIR, { recursive: true });
            } catch (error) {
                console.error('Failed to create cache directory:', error);
            }
        }
    }

    /**
     * Get the cache file path for an endpoint
     * @param {string} endpoint - The API endpoint
     * @returns {string} - The cache file path
     */
    _getCachePath(endpoint) {
        // Replace any special characters in the endpoint to create a valid filename
        const cacheFile = endpoint.replace(/[\/\?&]/g, '_');
        return path.join(this.CACHE_DIR, `${cacheFile}.json`);
    }

    /**
     * Get data from cache if available and not expired
     * @param {string} endpoint - The API endpoint
     * @returns {object|null} - The cached data or null if not available
     */
    _getFromCache(endpoint) {
        const cachePath = this._getCachePath(endpoint);

        if (!fs.existsSync(cachePath)) {
            return null;
        }

        try {
            const stats = fs.statSync(cachePath);
            const now = new Date().getTime();

            // Check if cache is expired
            if (now - stats.mtime.getTime() > this.CACHE_EXPIRY) {
                return null;
            }

            const data = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
            return data;
        } catch (error) {
            console.error('Cache read error:', error);
            return null;
        }
    }

    /**
     * Save data to cache
     * @param {string} endpoint - The API endpoint
     * @param {object} data - The data to cache
     */
    _saveToCache(endpoint, data) {
        const cachePath = this._getCachePath(endpoint);

        try {
            fs.writeFileSync(cachePath, JSON.stringify(data), 'utf8');
        } catch (error) {
            console.error('Cache write error:', error);
        }
    }

    /**
     * Make a request to the CWE API
     * @param {string} endpoint - The API endpoint
     * @returns {Promise<object>} - The API response
     */
    async _makeRequest(endpoint) {
        // Check cache first
        const cachedData = this._getFromCache(endpoint);
        if (cachedData) {
            return cachedData;
        }

        try {
            const url = `${this.BASE_URL}/${endpoint}`;
            const response = await axios.get(url);

            if (response.status === 200) {
                this._saveToCache(endpoint, response.data);
                return response.data;
            } else {
                throw new Error(`API request failed with status code ${response.status}`);
            }
        } catch (error) {
            if (error.response && error.response.status === 404) {
                throw new Error(`CWE not found: ${endpoint}`);
            }
            throw error;
        }
    }

    /**
     * Get the CWE version information
     * @returns {Promise<object>} - CWE version information
     */
    async getVersion() {
        return this._makeRequest('cwe/version');
    }

    /**
     * Get basic information about CWE IDs
     * @param {number|number[]|string} cweIds - A single CWE ID, a list of CWE IDs, or a comma-separated string of CWE IDs
     * @returns {Promise<object>} - CWE information
     */
    async getCWEInfo(cweIds) {
        if (Array.isArray(cweIds)) {
            cweIds = cweIds.join(',');
        }
        return this._makeRequest(`cwe/${cweIds}`);
    }

    /**
     * Get detailed information about CWE weaknesses
     * @param {number|number[]|string} cweIds - A single CWE ID, a list of CWE IDs, or a comma-separated string of CWE IDs
     * @returns {Promise<object>} - CWE weakness information
     */
    async getWeakness(cweIds) {
        if (Array.isArray(cweIds)) {
            cweIds = cweIds.join(',');
        }
        return this._makeRequest(`cwe/weakness/${cweIds}`);
    }

    /**
     * Get the parents of a CWE
     * @param {number} cweId - The CWE ID
     * @param {number} [viewId] - Optional view ID to filter by
     * @returns {Promise<object>} - Parent CWEs
     */
    async getParents(cweId, viewId) {
        let endpoint = `cwe/${cweId}/parents`;
        if (viewId) {
            endpoint += `?view=${viewId}`;
        }
        return this._makeRequest(endpoint);
    }

    /**
     * Get the children of a CWE
     * @param {number} cweId - The CWE ID
     * @param {number} [viewId] - Optional view ID to filter by
     * @returns {Promise<object>} - Child CWEs
     */
    async getChildren(cweId, viewId) {
        let endpoint = `cwe/${cweId}/children`;
        if (viewId) {
            endpoint += `?view=${viewId}`;
        }
        return this._makeRequest(endpoint);
    }

    /**
     * Get a simplified description of a CWE
     * @param {number} cweId - The CWE ID
     * @returns {Promise<object>} - Simplified CWE information
     */
    async getSimplifiedCWEInfo(cweId) {
        try {
            const weaknessInfo = await this.getWeakness(cweId);

            if (weaknessInfo && weaknessInfo.Weaknesses && weaknessInfo.Weaknesses.length > 0) {
                const weakness = weaknessInfo.Weaknesses[0];

                // Log the full weakness object to help debug
                console.log(`CWE-${cweId} data structure:`, JSON.stringify(weakness, null, 2).substring(0, 500) + '...');

                // Enhanced logging for mitigations
                if (weakness.Potential_Mitigations) {
                    console.log(`CWE-${cweId} has ${weakness.Potential_Mitigations.length} potential mitigations`);

                    // Log the first mitigation to understand its structure
                    if (weakness.Potential_Mitigations.length > 0) {
                        const firstMitigation = weakness.Potential_Mitigations[0];
                        console.log(`First mitigation structure:`, JSON.stringify(firstMitigation, null, 2));
                    }
                } else {
                    console.log(`CWE-${cweId} has no potential mitigations data in API response`);

                    // Try to fetch mitigations from a fallback source if available
                    try {
                        const fallbackMitigations = await this._getFallbackMitigations(cweId);
                        if (fallbackMitigations && fallbackMitigations.length > 0) {
                            console.log(`Found ${fallbackMitigations.length} fallback mitigations for CWE-${cweId}`);
                            weakness.Potential_Mitigations = fallbackMitigations;
                        }
                    } catch (fallbackError) {
                        console.error(`Error fetching fallback mitigations for CWE-${cweId}:`, fallbackError);
                    }
                }

                // Enhanced logging for consequences
                if (weakness.Common_Consequences) {
                    console.log(`CWE-${cweId} has ${weakness.Common_Consequences.length} common consequences`);

                    // Log the first consequence to understand its structure
                    if (weakness.Common_Consequences.length > 0) {
                        const firstConsequence = weakness.Common_Consequences[0];
                        console.log(`First consequence structure:`, JSON.stringify(firstConsequence, null, 2));
                    }
                } else {
                    console.log(`CWE-${cweId} has no common consequences data in API response`);

                    // Try to fetch consequences from a fallback source if available
                    try {
                        const fallbackConsequences = await this._getFallbackConsequences(cweId);
                        if (fallbackConsequences && fallbackConsequences.length > 0) {
                            console.log(`Found ${fallbackConsequences.length} fallback consequences for CWE-${cweId}`);
                            weakness.Common_Consequences = fallbackConsequences;
                        }
                    } catch (fallbackError) {
                        console.error(`Error fetching fallback consequences for CWE-${cweId}:`, fallbackError);
                    }
                }

                return {
                    id: cweId,
                    name: weakness.Name || `CWE-${cweId}`,
                    description: weakness.Description || `Common Weakness Enumeration ${cweId}`,
                    extendedDescription: weakness.Extended_Description || '',
                    likelihood: weakness.Likelihood_Of_Exploit || 'Unknown',
                    severity: this._mapCWESeverity(weakness),
                    mitigations: weakness.Potential_Mitigations || [],
                    consequences: weakness.Common_Consequences || [],
                    demonstrativeExamples: weakness.Demonstrative_Examples || [],
                    applicablePlatforms: weakness.Applicable_Platforms || {},
                    url: `https://cwe.mitre.org/data/definitions/${cweId}.html`
                };
            }

            // Fallback if API doesn't return expected data
            return {
                id: cweId,
                name: `CWE-${cweId}`,
                description: `Common Weakness Enumeration ${cweId}`,
                extendedDescription: '',
                likelihood: 'Unknown',
                severity: 'Unknown',
                mitigations: [],
                consequences: [],
                demonstrativeExamples: [],
                applicablePlatforms: {},
                url: `https://cwe.mitre.org/data/definitions/${cweId}.html`
            };
        } catch (error) {
            console.error(`Error getting CWE-${cweId} info:`, error);

            // Return minimal information on error
            return {
                id: cweId,
                name: `CWE-${cweId}`,
                description: `Common Weakness Enumeration ${cweId}`,
                extendedDescription: '',
                likelihood: 'Unknown',
                severity: 'Unknown',
                mitigations: [],
                consequences: [],
                demonstrativeExamples: [],
                applicablePlatforms: {},
                url: `https://cwe.mitre.org/data/definitions/${cweId}.html`
            };
        }
    }

    /**
     * Map CWE information to a severity level
     * @param {object} weakness - The CWE weakness object
     * @returns {string} - Severity level (Critical, High, Medium, Low)
     */
    _mapCWESeverity(weakness) {
        // Try to determine severity from CWE data
        const likelihood = weakness.Likelihood_Of_Exploit || '';

        if (likelihood.includes('High')) {
            return 'High';
        } else if (likelihood.includes('Medium')) {
            return 'Medium';
        } else if (likelihood.includes('Low')) {
            return 'Low';
        }

        // Default mapping based on common high-severity CWEs
        const highSeverityCWEs = [
            78, 79, 89, 94, 502, 798, 295, 287, 352, 434, 611, 22
        ];

        const mediumSeverityCWEs = [
            120, 134, 190, 330, 416, 476, 400, 601, 772, 863
        ];

        if (highSeverityCWEs.includes(parseInt(weakness.ID))) {
            return 'High';
        } else if (mediumSeverityCWEs.includes(parseInt(weakness.ID))) {
            return 'Medium';
        }

        return 'Medium'; // Default to medium if we can't determine
    }

    /**
     * Get fallback mitigations for a CWE when the API doesn't provide them
     * @param {number} cweId - The CWE ID
     * @returns {Promise<Array>} - Array of mitigation objects
     */
    async _getFallbackMitigations(cweId) {
        // Hardcoded fallback mitigations for common CWEs
        const fallbackMitigations = {
            // SQL Injection
            89: [
                {
                    Description: "Use prepared statements and parameterized queries. These are SQL statements that are sent to and parsed by the database server separately from any parameters.",
                    Phase: "Implementation"
                },
                {
                    Description: "Use an ORM (Object Relational Mapping) library to abstract database access and ensure proper escaping.",
                    Phase: "Implementation"
                },
                {
                    Description: "Validate all input: Ensure that user-supplied data is validated, filtered, or sanitized by the application.",
                    Phase: "Implementation"
                }
            ],
            // XSS
            79: [
                {
                    Description: "Use a Content Security Policy (CSP) to restrict what content can be loaded on your site.",
                    Phase: "Implementation"
                },
                {
                    Description: "Use context-sensitive escaping for all output to the browser. HTML encode data before inserting it into HTML element content.",
                    Phase: "Implementation"
                },
                {
                    Description: "Use frameworks that automatically escape XSS by design, such as React, Angular, or Vue.",
                    Phase: "Architecture and Design"
                }
            ],
            // Path Traversal
            22: [
                {
                    Description: "Validate user input before using it to construct file paths. Use allowlists of permitted values or patterns.",
                    Phase: "Implementation"
                },
                {
                    Description: "Use platform path functions to canonicalize paths before validating them.",
                    Phase: "Implementation"
                },
                {
                    Description: "Use a library or framework that does not allow path traversal or provides built-in protection.",
                    Phase: "Architecture and Design"
                }
            ],
            // Hard-coded Credentials
            798: [
                {
                    Description: "Store credentials in external configuration files or environment variables that are appropriately protected.",
                    Phase: "Implementation"
                },
                {
                    Description: "Use a secure credential management system or vault.",
                    Phase: "Architecture and Design"
                },
                {
                    Description: "Implement proper key rotation mechanisms and avoid using the same key for extended periods.",
                    Phase: "Operation"
                }
            ],
            // Weak Cryptography
            327: [
                {
                    Description: "Use strong, modern cryptographic algorithms and implementations that are actively maintained.",
                    Phase: "Architecture and Design"
                },
                {
                    Description: "Replace weak algorithms (DES, MD5, SHA1, RC4) with stronger alternatives (AES, SHA-256, ChaCha20).",
                    Phase: "Implementation"
                },
                {
                    Description: "Use established libraries and avoid implementing cryptographic algorithms yourself.",
                    Phase: "Architecture and Design"
                }
            ],
            // CSRF
            352: [
                {
                    Description: "Implement anti-CSRF tokens in forms and AJAX requests.",
                    Phase: "Implementation"
                },
                {
                    Description: "Use the SameSite cookie attribute to limit cross-site request forgery.",
                    Phase: "Implementation"
                },
                {
                    Description: "Verify the origin and referrer headers on requests that perform sensitive actions.",
                    Phase: "Implementation"
                }
            ],
            // SSRF
            918: [
                {
                    Description: "Implement a whitelist of allowed URLs or domains.",
                    Phase: "Implementation"
                },
                {
                    Description: "Disable support for redirects in HTTP libraries used by your application.",
                    Phase: "Implementation"
                },
                {
                    Description: "Use network-level protections to prevent the server from making requests to internal resources.",
                    Phase: "Architecture and Design"
                }
            ],
            // Weak Randomness
            330: [
                {
                    Description: "Use cryptographically secure random number generators for security-sensitive operations.",
                    Phase: "Implementation"
                },
                {
                    Description: "Avoid using Math.random() for security purposes; use crypto.getRandomValues() or similar APIs instead.",
                    Phase: "Implementation"
                },
                {
                    Description: "Ensure that random values have sufficient entropy for their intended use.",
                    Phase: "Implementation"
                }
            ],
            // Unrestricted Upload
            434: [
                {
                    Description: "Validate file types, extensions, and content before accepting uploads.",
                    Phase: "Implementation"
                },
                {
                    Description: "Store uploaded files outside the web root with restricted permissions.",
                    Phase: "Architecture and Design"
                },
                {
                    Description: "Use a content delivery network (CDN) or separate domain to serve uploaded files.",
                    Phase: "Architecture and Design"
                }
            ],
            // Integer Overflow
            190: [
                {
                    Description: "Use languages or libraries that handle integer overflow automatically.",
                    Phase: "Architecture and Design"
                },
                {
                    Description: "Perform range checking before performing arithmetic operations.",
                    Phase: "Implementation"
                },
                {
                    Description: "Use safe integer handling functions that detect and prevent overflow.",
                    Phase: "Implementation"
                }
            ],
            // Missing Encryption
            311: [
                {
                    Description: "Identify and encrypt sensitive data at rest and in transit.",
                    Phase: "Architecture and Design"
                },
                {
                    Description: "Use strong, standardized encryption algorithms and protocols (e.g., AES, TLS).",
                    Phase: "Implementation"
                },
                {
                    Description: "Implement proper key management practices, including secure key storage and rotation.",
                    Phase: "Implementation"
                }
            ],
            // Eval Injection
            95: [
                {
                    Description: "Avoid using eval(), new Function(), setTimeout() with string arguments, or other dynamic code execution features.",
                    Phase: "Implementation"
                },
                {
                    Description: "If dynamic code execution is necessary, strictly validate and sanitize the input.",
                    Phase: "Implementation"
                },
                {
                    Description: "Use safer alternatives like JSON.parse() for parsing JSON data.",
                    Phase: "Implementation"
                }
            ]
        };

        // Return fallback mitigations if available for this CWE
        return fallbackMitigations[cweId] || [];
    }

    /**
     * Get fallback consequences for a CWE when the API doesn't provide them
     * @param {number} cweId - The CWE ID
     * @returns {Promise<Array>} - Array of consequence objects
     */
    async _getFallbackConsequences(cweId) {
        // Hardcoded fallback consequences for common CWEs
        const fallbackConsequences = {
            // SQL Injection
            89: [
                {
                    Scope: ["Confidentiality", "Integrity", "Availability"],
                    Impact: ["Read Application Data", "Modify Application Data", "DoS: Crash, Exit, or Restart"],
                    Note: "SQL injection can lead to unauthorized access to sensitive data, data corruption, and in some cases, complete system compromise."
                }
            ],
            // XSS
            79: [
                {
                    Scope: ["Confidentiality", "Integrity"],
                    Impact: ["Execute Unauthorized Code or Commands", "Bypass Protection Mechanism", "Read Application Data"],
                    Note: "Cross-site scripting allows attackers to execute scripts in the victim's browser, potentially leading to cookie theft, session hijacking, and other client-side attacks."
                }
            ],
            // Path Traversal
            22: [
                {
                    Scope: ["Confidentiality", "Integrity", "Availability"],
                    Impact: ["Read Files or Directories", "Modify Files or Directories", "DoS: Crash, Exit, or Restart"],
                    Note: "Path traversal vulnerabilities can allow attackers to access files and directories stored outside the intended directory, potentially exposing sensitive information or modifying critical files."
                }
            ],
            // Hard-coded Credentials
            798: [
                {
                    Scope: ["Confidentiality", "Integrity", "Access Control"],
                    Impact: ["Gain Privileges or Assume Identity", "Bypass Protection Mechanism"],
                    Note: "Hard-coded credentials can be discovered through code inspection or reverse engineering, allowing attackers to gain unauthorized access to systems and data."
                }
            ],
            // Weak Cryptography
            327: [
                {
                    Scope: ["Confidentiality", "Integrity", "Access Control"],
                    Impact: ["Read Application Data", "Modify Application Data", "Bypass Protection Mechanism"],
                    Note: "Using weak cryptographic algorithms can allow attackers to decrypt sensitive data or forge signatures, compromising the security of the application."
                }
            ],
            // CSRF
            352: [
                {
                    Scope: ["Integrity", "Access Control"],
                    Impact: ["Modify Application Data", "Gain Privileges or Assume Identity"],
                    Note: "Cross-site request forgery vulnerabilities allow attackers to trick users into performing unintended actions on a web application in which they're authenticated."
                }
            ],
            // SSRF
            918: [
                {
                    Scope: ["Confidentiality", "Integrity", "Availability", "Access Control"],
                    Impact: ["Read Application Data", "Modify Application Data", "DoS: Crash, Exit, or Restart", "Bypass Protection Mechanism"],
                    Note: "Server-side request forgery can allow attackers to induce the server to make requests to internal resources, potentially bypassing firewalls and accessing sensitive internal services."
                }
            ],
            // Weak Randomness
            330: [
                {
                    Scope: ["Confidentiality", "Access Control"],
                    Impact: ["Bypass Protection Mechanism", "Gain Privileges or Assume Identity"],
                    Note: "Insufficient randomness can make it possible to predict values that were intended to be unpredictable, such as session IDs, passwords, or cryptographic keys."
                }
            ],
            // Unrestricted Upload
            434: [
                {
                    Scope: ["Confidentiality", "Integrity", "Availability"],
                    Impact: ["Execute Unauthorized Code or Commands", "DoS: Crash, Exit, or Restart"],
                    Note: "Unrestricted file upload can allow attackers to upload malicious files, potentially leading to code execution, content spoofing, or denial of service."
                }
            ],
            // Integer Overflow
            190: [
                {
                    Scope: ["Integrity", "Availability", "Access Control"],
                    Impact: ["DoS: Crash, Exit, or Restart", "Modify Memory", "Bypass Protection Mechanism"],
                    Note: "Integer overflow can lead to buffer overflows, memory corruption, and other vulnerabilities that may allow attackers to crash the application or execute arbitrary code."
                }
            ],
            // Missing Encryption
            311: [
                {
                    Scope: ["Confidentiality"],
                    Impact: ["Read Application Data", "Read Memory"],
                    Note: "Failure to encrypt sensitive data can expose it to unauthorized parties, potentially leading to data breaches and privacy violations."
                }
            ],
            // Eval Injection
            95: [
                {
                    Scope: ["Confidentiality", "Integrity", "Availability"],
                    Impact: ["Execute Unauthorized Code or Commands", "Modify Application Data", "Read Application Data"],
                    Note: "Eval injection can allow attackers to execute arbitrary code in the context of the application, potentially leading to complete system compromise."
                }
            ]
        };

        // Return fallback consequences if available for this CWE
        return fallbackConsequences[cweId] || [];
    }
}

module.exports = new CWEApiClient();
