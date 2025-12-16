# 🔒 Gemini-Powered Web Security Auditor

A comprehensive, AI-powered web security auditing tool that combines dynamic fuzzing with Google's Gemini AI for intelligent vulnerability analysis and detailed reporting.

## ✨ Features

- **🧪 Dynamic Fuzzing Engine**: Comprehensive security testing with extensive payload libraries
- **🤖 AI-Powered Analysis**: Uses Google Gemini AI for intelligent vulnerability assessment
- **📊 Rich Analytics**: Interactive dashboards with visualizations
- **💾 Database Storage**: SQLite database for audit history and results tracking
- **📄 PDF Reports**: Professional, detailed PDF reports with remediation advice
- **🎯 Multiple Vulnerability Types**: Detects SQLi, XSS, CSRF, IDOR, Buffer Overflow, and more
- **⚙️ Configurable Testing**: Customizable test parameters and payload selection
- **🔐 Secure Configuration**: Environment-based configuration management

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Google AI (Gemini) API key ([Get one here](https://makersuite.google.com/app/apikey))

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd GEMINI-POWERED-WEB-SECURITY-AUDITOR-
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   
   Create a `.env` file in the root directory:
   ```env
   GEMINI_API_KEY=your_api_key_here
   GEMINI_MODEL=gemini-1.5-pro
   FLASK_HOST=127.0.0.1
   FLASK_PORT=5000
   MAX_FUZZ_TESTS=100
   DEFAULT_FUZZ_TESTS=20
   ```

4. **Run the application**
   ```bash
   streamlit run app.py
   ```

   The application will open in your default web browser at `http://localhost:8501`

## 📁 Project Structure

```
GEMINI-POWERED-WEB-SECURITY-AUDITOR-/
├── app.py                 # Main Streamlit application
├── config.py             # Configuration management
├── database.py           # Database models and operations
├── fuzzer.py             # Fuzzing engine
├── analyzer.py           # AI-powered vulnerability analyzer
├── reporter.py           # PDF report generation
├── payloads.py           # Security testing payloads library
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── data/                # Data directory (created automatically)
│   ├── audit_results.db # SQLite database
│   └── cve_data.json    # CVE dataset
└── reports/             # Generated PDF reports
```

## 🎯 Usage

### Running a Security Audit

1. **Enter API Key**: In the sidebar, enter your Google AI API key
2. **Configure Test Parameters**:
   - Select number of tests (5-100)
   - Choose vulnerability types to test
   - Optionally add custom payloads
3. **Run Audit**: Click "🚀 Run Security Audit"
4. **Review Results**: 
   - View vulnerability findings in the data table
   - Explore analytics and visualizations
   - Review detailed findings with AI-generated remediation advice
5. **Download Report**: Generate and download a comprehensive PDF report

### Vulnerability Types Detected

- **SQL Injection**: Database query manipulation
- **Cross-Site Scripting (XSS)**: Script injection attacks
- **Cross-Site Request Forgery (CSRF)**: Unauthorized action execution
- **Insecure Direct Object Reference (IDOR)**: Unauthorized access to resources
- **Buffer Overflow**: Memory corruption attacks
- **Command Injection**: OS command execution
- **Path Traversal**: Directory traversal attacks
- **Session Fixation**: Weak session management
- **LDAP Injection**: LDAP query manipulation
- **XXE**: XML External Entity attacks

## 🏗️ Architecture

### Components

1. **Fuzzer** (`fuzzer.py`): 
   - Generates and sends security test payloads
   - Manages Flask server for testing
   - Classifies detected vulnerabilities

2. **Analyzer** (`analyzer.py`):
   - Integrates with Google Gemini AI for intelligent analysis
   - Falls back to ML models if AI is unavailable
   - Provides severity ratings, CVSS scores, and remediation advice

3. **Reporter** (`reporter.py`):
   - Generates professional PDF reports
   - Includes executive summaries, detailed findings, and recommendations

4. **Database** (`database.py`):
   - Stores audit results and history
   - Enables result tracking and retrieval

5. **Payloads** (`payloads.py`):
   - Comprehensive library of security testing payloads
   - Categorized by vulnerability type

## 🔧 Configuration

All configuration is managed through environment variables or the `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google AI API key | Required |
| `GEMINI_MODEL` | Gemini model to use | `gemini-1.5-pro` |
| `FLASK_HOST` | Flask server host | `127.0.0.1` |
| `FLASK_PORT` | Flask server port | `5000` |
| `MAX_FUZZ_TESTS` | Maximum tests per audit | `100` |
| `DEFAULT_FUZZ_TESTS` | Default test count | `20` |
| `REQUEST_TIMEOUT` | HTTP request timeout (seconds) | `10` |
| `DATABASE_URL` | Database connection string | SQLite default |
| `LOG_LEVEL` | Logging level | `INFO` |

## 📊 Features in Detail

### AI-Powered Analysis

The tool uses Google's Gemini AI to provide:
- Intelligent severity assessment
- CVSS score calculation
- Detailed risk justification
- Actionable remediation steps
- Impact analysis
- Exploitation likelihood assessment

### Comprehensive Fuzzing

- Extensive payload library with 100+ test cases
- Multiple vulnerability categories
- Custom payload support
- Configurable test types
- Real-time vulnerability detection

### Professional Reporting

PDF reports include:
- Executive summary with severity breakdown
- Vulnerability statistics
- Detailed findings with AI analysis
- Remediation recommendations
- Professional formatting and styling

## 🛡️ Security Considerations

⚠️ **Important**: This tool is designed for:
- Security testing of your own applications
- Authorized penetration testing
- Educational purposes
- Security research

**Do not use this tool on systems you don't own or have explicit permission to test.**

## 📝 License

This project is provided as-is for educational and security research purposes.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📧 Support

For issues, questions, or contributions, please open an issue on the repository.

## 🙏 Acknowledgments

- Google Gemini AI for intelligent vulnerability analysis
- Streamlit for the web interface
- OWASP for security testing guidelines
- The security research community for payload libraries

---

**Built with ❤️ for the security community**