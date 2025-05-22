# Testing the Vulnerability Scanner Extension

This folder contains test files for the Vulnerability Scanner extension.

## How to Test

1. Press F5 to launch the extension in debug mode
2. Open one of the test files (e.g., `debug.js` or `sample.js`)
3. Run the "Scan Current File for Vulnerabilities" command from the Command Palette (Ctrl+Shift+P)
4. Check the results in the Vulnerabilities Panel

## Test Files

- `debug.js`: Simple file with intentional vulnerabilities for testing
- `sample.js`: More complex file with various vulnerability types
- `test_vulnerable.js`: Test file with CWE-mapped vulnerabilities

## Expected Results

When scanning these files, the extension should:

1. Detect the vulnerabilities
2. Map them to appropriate CWE IDs
3. Display CWE information in the Vulnerabilities Panel
4. Show links to CWE documentation

## Troubleshooting

If the extension doesn't work:

1. Check the Debug Console for errors
2. Make sure the extension is activated (look for "Extension 'vulnerability-scanner' is now active!" in the console)
3. Try running the command from the Command Palette
4. Check if the status bar item is visible
