/**
 * This is a sample file with intentional vulnerabilities to test the CWE integration
 * DO NOT USE THIS CODE IN PRODUCTION!
 */

// CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
function evalExample(userInput) {
    // Vulnerable: Direct use of eval with user input
    eval(userInput);
    
    // Also vulnerable: Using Function constructor
    new Function(userInput)();
}

// CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
function xssExample(userInput) {
    // Vulnerable: Directly setting innerHTML with user input
    document.getElementById('output').innerHTML = userInput;
    
    // Also vulnerable: Using document.write
    document.write(userInput);
}

// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
function sqlInjectionExample(userId) {
    // Vulnerable: String concatenation in SQL query
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    executeQuery(query);
    
    // Also vulnerable: Template literals without parameterization
    const query2 = `SELECT * FROM users WHERE id = '${userId}'`;
    executeQuery(query2);
}

// Mock function for SQL execution
function executeQuery(query) {
    console.log(`Executing query: ${query}`);
    // In a real application, this would connect to a database
}
