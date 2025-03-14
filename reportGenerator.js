const fs = require("fs");
const path = require("path");

function generateReport(issues, filePath) {
  let report = `# SecureCode Security Report\n\n`;

  if (issues.length === 0) {
    report += "✅ No security vulnerabilities found!\n";
  } else {
    report += `⚠️ Found ${issues.length} security vulnerabilities:\n\n`;
    issues.forEach((issue, index) => {
      report += `**${index + 1}. ${issue.message}**\n`;
      report += `- 📍 **Line:** ${issue.line}\n\n`;
    });
  }

  const reportPath = path.join(filePath, "security-report.md");
  fs.writeFileSync(reportPath, report);
  return reportPath;
}

module.exports = { generateReport };
