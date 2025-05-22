// test-vulnerabilities.js
// Contains intentional security weaknesses for testing CWE analysis

// 1. CWE-259: Hard-coded Password
const dbPassword = 'supersecret123'; // Bad: Hardcoded credentials
const apiKey = 'AKIAXXXXXXXXXXXXXXXX'; // Bad: Hardcoded AWS key

// 2. CWE-89: SQL Injection
function getUser(username) {
    const query = `SELECT * FROM users WHERE username = '${username}'`; // Bad: Unsanitized input
    database.query(query);
}

// 3. CWE-79: XSS Vulnerability
function displayUserInput() {
    const userContent = document.getElementById('user-input').value;
    document.body.innerHTML = userContent; // Bad: Unsanitized DOM injection
}

// 4. CWE-327: Broken Crypto
function encryptData() {
    const crypto = require('crypto');
    const cipher = crypto.createCipher('des', 'weakkey'); // Bad: Weak DES algorithm
}

// 5. CWE-352: CSRF
app.post('/transfer', (req, res) => { // Bad: No CSRF protection
    bank.transfer(req.body.amount, req.body.account);
});

// 6. CWE-22: Path Traversal
function readFile() {
    const filename = req.query.file;
    fs.readFileSync(`/uploads/${filename}`); // Bad: Unsanitized file path
}

// 7. CWE-798: Hard-coded Credentials
const jwtSecret = 'secret'; // Bad: Weak JWT secret
const adminToken = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // Bad: Hardcoded token

// 8. CWE-918: SSRF
function fetchData() {
    const url = req.query.url;
    fetch(url); // Bad: Unrestricted URL fetching
}

// 9. CWE-330: Weak Randomness
function generateSessionId() {
    return Math.random().toString(36); // Bad: Cryptographically weak RNG
}

// 10. CWE-434: Unrestricted Upload
app.post('/upload', (req, res) => {
    const file = req.files.uploadedFile;
    file.mv('/uploads/' + file.name); // Bad: No file type validation
});

// 11. CWE-190: Integer Overflow
function processPayment(amount) {
    if (amount < 0) return;
    // Bad: No upper bound check
    account.balance += amount;
}

// 12. CWE-311: Missing Encryption
function storeUserData() {
    localStorage.setItem('privateData', JSON.stringify({ // Bad: Sensitive data in localStorage
        ssn: '123-45-6789',
        dob: '01/01/1970'
    }));
}

// 13. CWE-95: Eval Injection
function processUserInput(input) {
    eval(input); // Bad: Unsanitized eval of user input
}

// Another example using Function constructor
const userCode = req.body.code;
const dynamicFunction = new Function('param', userCode); // Bad: Unsafe code evaluation

// Example with setTimeout string
const userAction = "'; maliciousCode(); '";
setTimeout("console.log('User action: " + userAction + "')", 100); // Bad: String-based timer with injection

// Safe alternative
setTimeout(() => { // Good: Function-based timer
    console.log('Safe timer executed');
}, 100);

// 14. CWE-95: Indirect eval through JSONP
function handleJsonpResponse(callbackName, data) {
    const script = document.createElement('script');
    script.src = `https://api.example.com/data?callback=${callbackName}`; // Bad: Untrusted callback
    document.body.appendChild(script);
}

// Mixed with some safe patterns to test false positives
const safePassword = process.env.DB_PASSWORD; // Good: Environment variable
const safeQuery = 'SELECT * FROM users WHERE username = ?'; // Good: Parameterized query
const strongSecret = crypto.randomBytes(32).toString('hex'); // Good: Secure random