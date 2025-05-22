
const vscode = require('vscode');
const axios = require('axios');

// Google AI Gemini API configuration
const GEMINI_API_KEY = "AIzaSyCnWoKaQIu_ilZrvvZVyp7TiqAINTvtzSE";

// Function to call Gemini API directly with axios
async function callGeminiAPI(prompt) {
    try {
        console.log('Calling Google AI Gemini API directly with axios...');
        console.log('Request prompt (full):', prompt);

        // Make a direct API call using the correct endpoint from the documentation
        // Using gemini-2.0-flash model which is stable and available
        const response = await axios.post(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`,
            {
                contents: [
                    {
                        parts: [
                            {
                                text: prompt
                            }
                        ]
                    }
                ],
                generationConfig: {
                    temperature: 0.7,
                    maxOutputTokens: 500,  // Reduced token limit for faster, more concise responses
                    topP: 0.95,            // Increased topP for more focused responses
                    topK: 40
                }
            },
            {
                headers: {
                    'Content-Type': 'application/json'
                },
                timeout: 30000  // 30 second timeout to give the API more time to respond
            }
        );

        console.log('Received response from Gemini API');

        // Extract the text from the response
        if (response.data &&
            response.data.candidates &&
            response.data.candidates[0] &&
            response.data.candidates[0].content &&
            response.data.candidates[0].content.parts &&
            response.data.candidates[0].content.parts[0]) {

            const responseText = response.data.candidates[0].content.parts[0].text;
            console.log('Response text (truncated):', responseText.substring(0, 100) + '...');
            return responseText;
        } else {
            console.error('Invalid response format:', JSON.stringify(response.data, null, 2));
            throw new Error('Invalid response format from Gemini API');
        }
    } catch (error) {
        console.error('Error calling Gemini API:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', JSON.stringify(error.response.data, null, 2));
        }
        throw error;
    }
}

class AttackSimulator {
    static async generateProofOfConcept(vulnerability) {
        console.log('generateProofOfConcept called with vulnerability:', JSON.stringify(vulnerability, null, 2));

        // Validate vulnerability object
        if (!vulnerability || !vulnerability.type || !vulnerability.message || !vulnerability.codeSnippet) {
            console.error('Invalid vulnerability object for PoC generation:', vulnerability);
            vscode.window.showErrorMessage('Invalid vulnerability data. Cannot generate proof of concept.');
            return 'Invalid vulnerability data. Cannot generate proof of concept.';
        }

        try {
            console.log('Preparing proof of concept for vulnerability type:', vulnerability.type);

            // Very simple prompt for Gemini API with instructions to keep it brief
            const prompt = `Create a brief proof-of-concept exploit for this vulnerability:
Type: ${vulnerability.type}
Details: ${vulnerability.message}
Code: ${vulnerability.codeSnippet}

Keep your response short and concise (max 300 words). Include:
1. A simple exploit code example (5-10 lines)
2. Brief explanation of how it works
3. Basic safety precautions

Be direct and to the point.`;

            console.log('Sending request to Google AI Gemini API...');

            try {
                // Call the Gemini API
                const geminiResponse = await callGeminiAPI(prompt);
                console.log('Received response from Gemini API');

                // Format the response if needed
                let formattedResponse = geminiResponse;

                // If the response doesn't start with a markdown heading, add one
                if (!formattedResponse.startsWith('# ')) {
                    formattedResponse = `# Proof of Concept for ${vulnerability.type}\n\n${formattedResponse}`;
                }

                return formattedResponse;

            } catch (apiError) {
                console.error('Error calling Gemini API:', apiError);
                console.log('Falling back to hardcoded response');

                // Generate a simple exploit based on the vulnerability type as a fallback
                let exampleExploit = '';
                if (vulnerability.type.toLowerCase().includes('sql injection')) {
                    exampleExploit = `const maliciousInput = "' OR 1=1; --";
const query = "SELECT * FROM users WHERE username = '" + maliciousInput + "'";
// This would return all users in the database`;
                } else if (vulnerability.type.toLowerCase().includes('xss')) {
                    exampleExploit = `const maliciousInput = "<script>alert('XSS Attack');</script>";
document.getElementById('userContent').innerHTML = maliciousInput;
// This would execute the script in the victim's browser`;
                } else if (vulnerability.type.toLowerCase().includes('command injection')) {
                    exampleExploit = `const userInput = "file.txt; rm -rf /important-files";
const command = "cat " + userInput;
exec(command);
// This would execute the malicious command`;
                } else {
                    exampleExploit = `// Generic exploit for ${vulnerability.type}
const maliciousInput = "Malicious payload here";
processUserInput(maliciousInput);
// This could lead to unexpected behavior`;
                }

                return `# 🔍 Proof of Concept for ${vulnerability.type} (AI Unavailable)

---

## 🛑 Vulnerability Details
${vulnerability.message}

---

## 📝 Code Context
\`\`\`
${vulnerability.codeSnippet}
\`\`\`

---

## 💻 Exploit Code
\`\`\`
// This is a simulated proof-of-concept exploit
// The AI service was unavailable, so this is a generic example

${exampleExploit}
\`\`\`

---

## ⚙️ How It Works
This exploit takes advantage of the vulnerability by manipulating the input in a way that bypasses security controls.

---

## 📋 Expected Output
When successful, the exploit would allow an attacker to:
- Gain unauthorized access
- Execute arbitrary code
- Access sensitive data

---

## 🛡️ Safety Precautions
- Always test in an isolated environment
- Obtain proper authorization before testing
- Monitor system behavior during testing
- Revert changes after testing is complete

---

> ℹ️ **Note**: This is a fallback response because the AI service was unavailable. For a more detailed and accurate analysis, please try again later.`;
            }
        } catch (error) {
            console.error('Error generating PoC:', error);
            const errorMessage = error.message || 'Unknown error';
            vscode.window.showErrorMessage(`Error generating proof-of-concept: ${errorMessage}`);
            return `Could not generate proof-of-concept. Error: ${errorMessage}`;
        }
    }

    static async simulateAttack(vulnerability) {
        // Status bar message reference
        let loadingMessage = null;

        try {
            console.log('AttackSimulator.simulateAttack called with vulnerability:', JSON.stringify(vulnerability, null, 2));

            // If vulnerability is not valid, create a test vulnerability for debugging
            if (!vulnerability || !vulnerability.type || !vulnerability.message || !vulnerability.codeSnippet) {
                console.warn('Invalid vulnerability object, creating test vulnerability for debugging');
                vulnerability = {
                    type: 'SQL Injection',
                    message: 'Unsanitized user input is directly used in SQL query',
                    codeSnippet: 'const query = "SELECT * FROM users WHERE username = \'" + username + "\'";',
                    line: 1,
                    severity: 'High'
                };
                console.log('Created test vulnerability:', vulnerability);
            }

            // Force enable AI features for attack simulation
            console.log('Ensuring AI features are enabled for attack simulation');

            // Set enableAI to true regardless of current setting
            await vscode.workspace.getConfiguration('vulnerabilityScanner').update('enableAI', true, vscode.ConfigurationTarget.Global);

            // Double-check that AI is enabled
            const enableAI = vscode.workspace.getConfiguration('vulnerabilityScanner').get('enableAI');
            console.log('AI features enabled:', enableAI);

            // Using Google AI Gemini API
            console.log('Using Google AI Gemini API for attack simulation');

            // Show a loading message as a notification in the bottom right corner
            loadingMessage = vscode.window.setStatusBarMessage(`$(loading~spin) Generating proof of concept for ${vulnerability.type}...`);

            // Also show an information message that doesn't block the UI
            vscode.window.showInformationMessage(
                `Generating proof of concept for ${vulnerability.type}. This may take up to 30 seconds...`
            );

            // Generate proof of concept
            console.log('Generating proof of concept...');
            const poc = await this.generateProofOfConcept(vulnerability);
            console.log('PoC generated successfully');

            // Format the PoC response to make it more visually appealing
            console.log('Formatting PoC response...');

            // Process the response to make it more visually appealing
            let formattedPoc = poc;

            // If the response doesn't start with a heading, add one
            if (!formattedPoc.startsWith('# ')) {
                formattedPoc = `# Proof of Concept for ${vulnerability.type}\n\n${formattedPoc}`;
            }

            // Add some visual enhancements
            formattedPoc = formattedPoc
                // Add emoji to headings for visual appeal
                .replace(/^# (.+)$/gm, '# 🔍 $1')
                .replace(/^## Vulnerability Details/gm, '## 🛑 Vulnerability Details')
                .replace(/^## Exploit Code/gm, '## 💻 Exploit Code')
                .replace(/^## How It Works/gm, '## ⚙️ How It Works')
                .replace(/^## Expected Output/gm, '## 📋 Expected Output')
                .replace(/^## Safety Precautions/gm, '## 🛡️ Safety Precautions')
                // Add horizontal rules for better section separation
                .replace(/^## /gm, '\n---\n\n## ');

            // Create a new document with the formatted PoC
            console.log('Creating document with formatted PoC...');
            const doc = await vscode.workspace.openTextDocument({
                content: formattedPoc,
                language: 'markdown'
            });

            // Show the document
            console.log('Showing document...');
            await vscode.window.showTextDocument(doc);
            console.log('Attack simulation completed successfully');

            // Keep AI features enabled for future use
            console.log('Keeping AI features enabled for future use');
        } catch (error) {
            console.error('Error simulating attack:', error);
            vscode.window.showErrorMessage(`Error simulating attack: ${error.message || 'Unknown error'}`);

            try {
                // Fallback to a simple document if everything else fails
                const doc = await vscode.workspace.openTextDocument({
                    content: `# ❌ Attack Simulation Error\n\n` +
                             `---\n\n` +
                             `## 🚨 Error Details\n\n` +
                             `An error occurred while simulating the attack:\n\n` +
                             `\`\`\`\n${error.message || 'Unknown error'}\n\`\`\`\n\n` +
                             `---\n\n` +
                             `## 🔍 Troubleshooting\n\n` +
                             `- Please check the console logs for more details\n` +
                             `- Try again later as the AI service might be temporarily unavailable\n` +
                             `- Verify your internet connection\n\n` +
                             `> ℹ️ If the problem persists, try using a different vulnerability type or code snippet.`,
                    language: 'markdown'
                });
                await vscode.window.showTextDocument(doc);
            } catch (fallbackError) {
                console.error('Failed to show fallback error document:', fallbackError);
            }
        } finally {
            // Always clear the loading message when done
            if (loadingMessage) {
                loadingMessage.dispose();
            }
        }
    }
}

module.exports = AttackSimulator;