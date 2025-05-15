const vscode = require('vscode');
const { OpenAI } = require('openai');

// Initialize OpenAI instance (replace 'YOUR_OPENAI_API_KEY' with your actual API key or use environment variable)
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY || 'APIKEY'
});

class AttackSimulator {
    static async generateProofOfConcept(vulnerability) {
        try {
            const prompt = `Generate a proof-of-concept exploit for a ${vulnerability.type} vulnerability.
            Vulnerability details: ${vulnerability.message}
            Code context: ${vulnerability.codeSnippet}
            
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
        } catch (error) {
            console.error('Error generating PoC:', error);
            return 'Could not generate proof-of-concept.';
        }
    }

    static async simulateAttack(vulnerability) {
        const poc = await this.generateProofOfConcept(vulnerability);
        
        // Create a new document with the PoC
        const doc = await vscode.workspace.openTextDocument({
            content: `# Proof of Concept for ${vulnerability.type}\n\n${poc}`,
            language: 'markdown'
        });
        
        await vscode.window.showTextDocument(doc);
    }
}

module.exports = AttackSimulator;