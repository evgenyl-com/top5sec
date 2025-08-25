# 🔐 top5sec

**top5sec** is a fast, modular AWS security scanner that automatically identifies and explains your account's top 5 most critical security risks. It provides actionable, step-by-step remediation guidance for each finding, making cloud security simple and effective for everyone.

---

## ✨ Features
- 🚀 **Automated AWS Security Scanning**: Uses AWS SDK & APIs to scan your account in minutes
- 🛡️ **Top 5 Critical Issues Only**: No noise, no 200-page reports—just the most urgent risks
- 📖 **Clear Explanations**: Each finding includes a human-readable description and impact
- 🛠️ **Step-by-Step Remediation**: Practical instructions to fix every issue
- 🧩 **Modular & Extensible**: Easily add custom rules or integrate into CI/CD pipelines
- 📊 **Beautiful HTML Reports**: Shareable, mobile-friendly, and print-ready security summaries

---

## 📦 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/your-org/top5sec.git
cd top5sec
pip install -r requirements.txt
```

---

## 🚦 Usage

Run the scanner with your AWS credentials (profile, environment variables, or assumed role):

```bash
python app/main.py
```

- The scanner will connect to your AWS account, run all security audits, and generate a static HTML report (`top5sec_report.html`).
- Open the report in your browser to review findings, impacts, and recommended fixes.

---

## 🔍 What Does It Check?

- **CloudTrail Logging**: Detects missing or incomplete logging across regions
- **IAM Users & Keys**: Finds users with console access, no MFA, or active access keys
- **Public Subnets & Security Groups**: Flags world-open resources and risky network exposure
- **S3 Bucket Exposure**: Identifies public buckets and risky ACLs
- **Encryption**: Reports unencrypted EBS volumes, RDS databases, and SNS topics
- **IAM Role Trusts**: Highlights risky cross-account trust relationships
- **VPC S3 Endpoint Coverage**: Finds subnets missing secure S3 endpoints

---

## 📄 Report Example

- Each finding is shown in a visually distinct block with severity, details, impact, and remediation steps
- Only findings with real risks are shown—"No data available" blocks are hidden
- Impact and recommendations are highlighted for quick action
- "Show more" buttons let you expand long details
- Print and share the report easily

---

## 🛠️ Customization & Extensibility

- Add new audit modules by creating a Python file in `app/` and returning a dict with a score and details
- Integrate with CI/CD by running the scanner in your pipeline and reviewing the HTML report
- Use environment variables or AWS profiles for flexible credential management

---

## 🤝 Contributing

Pull requests, feature suggestions, and bug reports are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📚 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 💡 Why top5sec?

Cloud security should be clear, actionable, and fast. top5sec helps you focus on what matters most—fixing your biggest risks, not reading endless reports.
