# 🦅 EndPointHawk - AI-Powered API Attack Surface Discovery

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Framework Support](https://img.shields.io/badge/frameworks-10+-green.svg)](#supported-frameworks)

> **Enterprise-grade API security discovery tool that automatically finds, analyzes, and risk-scores endpoints across your entire microservice architecture**

**Protect your APIs before they become vulnerabilities** - EndPointHawk discovers hidden attack surfaces that traditional security tools miss.

Developed by **[@rootranjan](https://github.com/rootranjan)** 

---

## 🎯 **The Critical Security Gap We Address**

### **💥 The Hidden API Security Crisis**

**Modern applications are leaking attack surfaces faster than security teams can discover them.** While organizations invest millions in perimeter security, their internal APIs remain invisible and unprotected.

**The Reality:**
- **Unknown endpoints = Unprotected vulnerabilities** - Every undiscovered API is a potential breach vector
- **Microservice sprawl creates blind spots** - 100+ services with 1000+ endpoints impossible to track manually
- **Security reviews can't keep up** - APIs change faster than security teams can assess them
- **Traditional tools miss dynamic routes** - Template literals, environment variables, and dynamic routing create invisible endpoints
- **No unified view** - Security teams struggle to get a complete picture across frameworks and services

### **🛡️ Why This Matters**

**Every undiscovered API endpoint is a potential:**
- **Data breach** - Exposing sensitive customer information
- **Privilege escalation** - Unauthorized access to admin functions  
- **Service disruption** - Attackers targeting critical business functions
- **Compliance violation** - Regulatory fines and legal consequences
- **Reputation damage** - Loss of customer trust and business impact

### **🎯 How EndPointHawk Solves This**

**EndPointHawk provides the missing layer of API security intelligence** that automatically discovers, analyzes, and risk-scores every endpoint across your entire microservice architecture - before attackers can find them.

**We transform invisible attack surfaces into actionable security intelligence.**

---

## 🚀 **Key Features**

### 🔍 **Multi-Framework API Discovery**
- **10+ Framework Support**: NestJS, Express, FastAPI, Spring Boot, Go, Django, Flask, NextJS, Ruby Rails, Laravel
- **Smart Pattern Matching**: Regex-based detection with framework-specific optimizations
- **Template Resolution**: Resolves dynamic routes and environment variables

### 🧠 **AI-Powered Analysis** 
- **Gemini Integration**: Advanced semantic analysis of route security
- **Risk Scoring**: Automated vulnerability assessment (0-100 scale)
- **Security Insights**: CWE mapping and remediation recommendations

### 📊 **Enterprise-Grade Reporting**
- **Multiple Formats**: JSON, HTML, CSV, SARIF for security tools
- **Rich Dashboards**: Interactive reports with risk breakdowns
- **Compliance Ready**: Enterprise security reporting standards

### 🔄 **Change Tracking & Comparison**
- **Git Integration**: Compare API changes between branches/tags/releases
- **Directory Comparison**: Analyze differences between deployments
- **Risk Impact Analysis**: Assess security implications of route changes

### ⚡ **Performance Optimized**
- **Intelligent Caching**: Faster re-scans with smart cache management
- **Parallel Processing**: Multi-threaded scanning for large codebases
- **Memory Efficient**: Optimized for enterprise-scale repositories

---

## 📦 **Installation Guide**

### **Prerequisites**
- Python 3.8 or higher
- pip (Python package installer)
- Git (for comparison features)

### **Quick Installation (Recommended)**

```bash
# 1. Clone the repository
git clone https://github.com/rootranjan/endpointhawk.git
cd endpointhawk

# 2. Install dependencies
python3 -m pip install -r requirements.txt

# 3. Verify installation
python3 endpointhawk.py --help
```

### **Alternative Installation Options**

#### **Option 1: Virtual Environment (Recommended for Development)**

```bash
# 1. Clone the repository
git clone https://github.com/rootranjan/endpointhawk.git
cd endpointhawk

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate   # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Use the tool
python3 endpointhawk.py --help
```

#### **Option 2: Global Installation**

```bash
# Install globally (requires sudo/admin)
sudo pip install -e .
endpointhawk --help
```

#### **Option 3: Web Interface**

```bash
# Start the web interface
python3 web_cli_bridge.py

# Open in browser: http://localhost:8182
```

### **First Scan (Get Started in 30 Seconds)**

```bash
# Navigate to your project directory
cd /path/to/your/project

# Run your first scan
python3 /path/to/endpointhawk/endpointhawk.py --repo-path . --frameworks auto

# View results in terminal or check the generated reports
```

### **Usage Options**

#### **Direct CLI Usage (Recommended)**
```bash
# Scan a repository
python3 endpointhawk.py --repo-path /path/to/repo --frameworks auto

# Scan with specific frameworks
python3 endpointhawk.py --repo-path /path/to/repo --frameworks nextjs,express

# Generate different output formats
python3 endpointhawk.py --repo-path /path/to/repo --output-format json,csv,sarif
```

#### **Web Interface**
```bash
# Start the web interface
python3 web_cli_bridge.py

# Open in browser: http://localhost:8182
```

#### **Package Installation (Optional)**
```bash
# Install as package for global access
pip install -e .
endpointhawk --help
endpointhawk-web  # Web interface
```

### **Troubleshooting**

#### **Import Errors**
If you see import errors like:
```
import rich.console could not be resolved
import flask_cors could not be resolved
```

**Solution:** Install the dependencies:
```bash
python3 -m pip install -r requirements.txt
```

#### **Common Issues**

1. **"command not found: pip"**
   - Use `python3 -m pip` instead of `pip`
   - Or install pip: `python3 -m ensurepip --upgrade`

2. **Permission errors**
   - Use `python3 -m pip install --user -r requirements.txt`
   - Or use a virtual environment

3. **Python version issues**
   - Ensure Python 3.8+ is installed
   - Check with: `python3 --version`

#### **Virtual Environment (Recommended)**
```bash
# Create virtual environment
python3 -m venv venv

# Activate (macOS/Linux)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Use EndPointHawk
python3 endpointhawk.py --help
```

### **Dependencies**

#### **Core Dependencies**
- `click>=8.0.0` - CLI framework
- `rich>=13.0.0` - Terminal formatting and progress bars
- `pydantic>=2.0.0` - Data models and validation
- `pyyaml>=6.0` - YAML configuration files

#### **Web Interface Dependencies**
- `flask>=2.3.0` - Web framework
- `flask-cors>=4.0.0` - Cross-origin resource sharing

#### **Configuration**
- `pyyaml>=6.0` - YAML configuration files
- `schedule>=1.2.0` - Task scheduling

#### **AI Analysis**
- `google-generativeai>=0.3.0` - Google Gemini AI integration

#### **Git Features**
- `GitPython>=3.1.40` - Git repository operations
- `pathspec>=0.11.0` - Enhanced gitignore pattern matching
- `jsondiff>=2.0.0` - Enhanced JSON diffing

### **Support**

If you encounter issues:
1. Check this troubleshooting guide
2. Ensure all dependencies are installed
3. Try using a virtual environment
4. Check Python version compatibility
5. Open an issue on GitHub with error details

### **Common Issues & Solutions**

#### **🚨 Import Errors**
```bash
# Error: ModuleNotFoundError: No module named 'rich'
# Solution: Install dependencies
python3 -m pip install -r requirements.txt
```

#### **🔧 Permission Issues**
```bash
# Error: Permission denied
# Solution: Use virtual environment or --user flag
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### **🐍 Python Version Issues**
```bash
# Error: Python version not supported
# Solution: Check Python version
python3 --version  # Should be 3.8+

# Install Python 3.8+ if needed
# macOS: brew install python@3.9
# Ubuntu: sudo apt install python3.9
# Windows: Download from python.org
```

#### **📁 Path Issues**
```bash
# Error: Repository path not found
# Solution: Use absolute paths or check directory
python3 endpointhawk.py --repo-path /absolute/path/to/repo
```

#### **🌐 Network Issues**
```bash
# Error: Cannot connect to Gemini API
# Solution: Check internet connection and API key
export GEMINI_API_KEY=your_api_key_here
# Or disable AI analysis: --no-ai
```

#### **💾 Memory Issues**
```bash
# Error: Out of memory on large repositories
# Solution: Use memory-optimized mode
python3 endpointhawk.py --repo-path . --performance-mode memory-optimized --max-memory 512
```

---

## 🚀 **Quick Start**

### **Your First Scan (Beginner)**

```bash
# 1. Basic scan of current directory
python3 endpointhawk.py --repo-path . --frameworks auto

# 2. Scan with HTML report
python3 endpointhawk.py --repo-path . --output-format html --output-dir ./reports

# 3. Open the HTML report in your browser
open ./reports/endpointhawk_report.html  # macOS
# xdg-open ./reports/endpointhawk_report.html  # Linux
# start ./reports/endpointhawk_report.html     # Windows
```

### **Security-Focused Scanning (Intermediate)**

```bash
# Scan with AI analysis and high-risk detection
python3 endpointhawk.py \
  --repo-path . \
  --use-ai \
  --risk-threshold high \
  --output-format html,sarif

# Compare API changes between versions
python3 endpointhawk.py \
  --repo-path . \
  --compare-tags v1.0.0,v2.0.0
```

### **Advanced Usage (Expert)**

```bash
# Comprehensive analysis with all features
python3 endpointhawk.py \
  --repo-path /path/to/your/project \
  --use-ai \
  --risk-threshold high \
  --output-format html,csv,sarif \
  --performance-mode fast \
  --cache-enabled

# Performance-optimized scan for large repositories
python3 endpointhawk.py \
  --repo-path /path/to/your/project \
  --performance-mode fast \
  --cache-enabled \
  --max-workers 8

# Web interface for interactive analysis
python3 web_cli_bridge.py
# Access dashboard at http://localhost:8182
```

---

## ⚙️ **Configuration**

### **Environment Variables**

Create `.env` file for optional features:

```bash
# AI Analysis (Optional)
GEMINI_API_KEY=your_gemini_api_key_here

# GitLab Integration (Optional) 
GITLAB_TOKEN=your_gitlab_token_here
GITLAB_URL=https://gitlab.com

# Web Interface
FLASK_ENV=development
SECRET_KEY=your_secret_key_here
```

### **Framework Configuration**

```bash
# Auto-detect frameworks (default)
--frameworks auto

# Specify frameworks explicitly
--frameworks nestjs,express,fastapi,go

# Scan all supported frameworks
--frameworks all
```

### **Output Configuration**

```bash
# Terminal output (default)
--output-format terminal

# Multiple formats
--output-format json,html,csv,sarif

# Custom output directory
--output-dir ./security-reports
```

### **Performance Tuning**

```bash
# Memory optimization for large repos
--performance-mode memory-optimized --max-memory 2048

# Fast scanning mode
--performance-mode fast --max-workers 8

# Enable intelligent caching
--cache-enabled --cache-cleanup 7
```

### **Simple Configuration Example**

Create a `config.yaml` file for custom settings:

```yaml
# config.yaml
version: '1.0'

# Organization settings
organization:
  organization_name: "My Company"
  security_baseline: "standard"

# Enable specific frameworks
frameworks:
  enabled_frameworks:
    - "nestjs"
    - "express"
    - "fastapi"

# Security settings
security:
  default_risk_threshold: "medium"
  enable_ai_analysis: true

# Output settings
output:
  default_formats:
    - "html"
    - "json"
```

Use the configuration:
```bash
python3 endpointhawk.py --repo-path . --config config.yaml
```

---

## 🔧 **Supported Frameworks**

| Framework | Language | Detection Features | Template Support |
|-----------|----------|-------------------|------------------|
| **NestJS** | TypeScript/JavaScript | Controllers, Decorators, Guards | ✅ Variables & Enums |
| **Express** | JavaScript | Routes, Middleware, Routers | ✅ Template Literals |
| **FastAPI** | Python | Path Operations, Dependencies | ✅ Path Parameters |
| **Spring Boot** | Java | Controllers, REST Mappings | ✅ Path Variables |
| **Go HTTP** | Go | Handlers, Mux Routers | ✅ Route Patterns |
| **Django** | Python | URLs, Views, Class-Based Views | ✅ URL Patterns |
| **Flask** | Python | Routes, Blueprints | ✅ Variable Rules |
| **NextJS** | TypeScript/JavaScript | API Routes, App Router | ✅ Dynamic Routes |
| **Ruby Rails** | Ruby | Routes, Controllers | ✅ RESTful Routes |
| **Laravel** | PHP | Routes, Controllers | ✅ Route Parameters |

---

## 📊 **Example Output**

### **Terminal Report**
```
🦅 EndPointHawk Attack Surface Discovery Complete!

┌─────────────────────┬─────────┐
│ Metric              │ Count   │
├─────────────────────┼─────────┤
│ Total Routes        │ 1,247   │
│ High Risk Routes    │ 23      │
│ Medium Risk Routes  │ 156     │
│ Low Risk Routes     │ 1,068   │
│ Services Found      │ 12      │
│ Frameworks Detected │ 4       │
│ Scan Duration       │ 3.2s    │
└─────────────────────┴─────────┘

🚨 High Risk Routes:
• DELETE /admin/users/:id (Unauthenticated admin endpoint)
• POST /api/exec (Command execution endpoint)
• GET /debug/env (Environment disclosure)
```

### **JSON Output Sample**
```json
{
  "scan_id": "hawk_20240120_143022",
  "total_routes": 1247,
  "high_risk_routes": 23,
  "frameworks_detected": ["nestjs", "express", "fastapi"],
  "routes": [
    {
      "path": "/api/v1/users/:id",
      "method": "GET",
      "framework": "express",
      "authenticated": true,
      "risk_score": 25.5,
      "security_findings": []
    }
  ]
}
```

## 🔍 **Security Findings**

EndPointHawk analyzes API routes and endpoints to identify potential security vulnerabilities and risks. Each finding includes a severity level, description, and recommendations for mitigation.

### **Finding Types**

#### **Authentication & Authorization**
- **Missing Authentication** (HIGH) - API endpoint lacks authentication mechanisms
- **Weak Authentication** (MEDIUM) - Authentication mechanism is present but may be weak  
- **Missing Authorization** (HIGH) - Endpoint lacks proper authorization checks

#### **Input Validation**
- **Missing Input Validation** (MEDIUM) - API parameters lack proper validation
- **Weak Input Validation** (LOW) - Input validation is present but may be insufficient

#### **Data Exposure**
- **Sensitive Data Exposure** (HIGH) - Endpoint may expose sensitive information
- **Excessive Data Exposure** (MEDIUM) - Endpoint returns more data than necessary

#### **Security Headers**
- **Missing Security Headers** (MEDIUM) - API responses lack important security headers

#### **Rate Limiting**
- **Missing Rate Limiting** (MEDIUM) - API endpoint lacks rate limiting

#### **Error Handling**
- **Information Disclosure in Errors** (MEDIUM) - Error responses may reveal sensitive information

#### **API Design**
- **Insecure Direct Object Reference** (HIGH) - API uses predictable resource identifiers
- **Missing CSRF Protection** (MEDIUM) - API lacks CSRF protection mechanisms

### **Risk Levels**

- **HIGH** - Critical security vulnerabilities requiring immediate attention
- **MEDIUM** - Moderate security risks to be addressed in reasonable timeframe
- **LOW** - Minor security concerns for regular maintenance

### **Recommendations**

1. **Prioritize HIGH severity findings** for immediate remediation
2. **Review MEDIUM severity findings** within the next sprint/iteration
3. **Address LOW severity findings** during regular code reviews
4. **Implement security testing** in your CI/CD pipeline
5. **Regular security audits** of your API endpoints

---

## 🤝 **Join the Security Community**

### **🛡️ Why Your Contribution Matters**

Every contribution to EndPointHawk directly impacts **API security worldwide**. Whether you're a security researcher, developer, or DevOps engineer, your expertise helps protect thousands of APIs from vulnerabilities.

**Your contributions help:**
- 🔍 **Discover hidden attack surfaces** in modern microservices
- 🚨 **Prevent data breaches** through early vulnerability detection  
- ⚡ **Accelerate security reviews** with automated analysis
- 🎯 **Protect real applications** used by millions of users

### **🚀 How to Get Started**

📖 **Complete contributor guide: [CONTRIBUTING.md](CONTRIBUTING.md)**

**Most impactful contributions:**
- **🔧 Framework Support** - Add detection for new frameworks (Spring Boot, FastAPI, etc.)
- **🛡️ Security Rules** - Enhance vulnerability detection algorithms
- **⚡ Performance** - Optimize scanning for large enterprise codebases
- **📊 Reporting** - Improve security findings and risk assessment
- **🌐 Integration** - Add support for CI/CD pipelines and security tools

### **💪 Real Impact Examples**

- **Framework Detection**: Your new detector could secure 1000+ APIs using that framework
- **Security Rules**: Your vulnerability pattern could prevent the next major breach
- **Performance**: Your optimization could scan enterprise repos 10x faster
- **Documentation**: Your guide could help 100+ security teams adopt EndPointHawk

**Ready to make a difference?** Start with [CONTRIBUTING.md](CONTRIBUTING.md) 🦅

---

## 📋 **Roadmap**

### **🚀 Coming Soon**
- **🔗 CI/CD Integration** - Automated security scanning in GitHub Actions, GitLab CI, Jenkins
- **💻 IDE Extensions** - Real-time API discovery in VS Code, IntelliJ, Eclipse
- **☸️ Kubernetes Discovery** - Runtime API endpoint discovery in containerized environments
- **🔍 GraphQL Analysis** - Schema and resolver security analysis
- **📄 API Spec Generation** - Auto-generate OpenAPI/Swagger documentation

### **🎯 Enterprise Features**
- **☁️ Cloud Integration** - AWS API Gateway, Azure APIM, Google Cloud Endpoints
- **🤖 Advanced AI Models** - Custom vulnerability detection and pattern learning
- **📊 Advanced Analytics** - Security trend analysis and compliance reporting
- **🔐 SSO Integration** - Enterprise authentication and role-based access
- **📈 Performance Monitoring** - Real-time scanning performance metrics

### **🌐 Community Requests**
- **🔧 Plugin System** - Extensible framework for custom detectors
- **📱 Mobile API Support** - iOS/Android API endpoint discovery
- **🌍 Multi-language Support** - Internationalization for global teams
- **📚 Learning Resources** - Interactive tutorials and security best practices

---

## 📜 **License**

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

### **What this means:**
- ✅ **Free for non-commercial use** - Open source, research, education
- ✅ **Modification allowed** - Fork, modify, improve
- ✅ **Distribution allowed** - Share with others
- ⚠️  **Commercial use restrictions** - Contact for commercial licensing
- 📋 **Source code disclosure required** - Any modifications must be open source

### **Commercial Licensing**
For commercial use, enterprise support, or proprietary integrations, please contact:
- **📧 Email**: rootranjan+endpointhawk@gmail.com
- **💬 GitHub**: [@rootranjan](https://github.com/rootranjan)

---

## 👨‍💻 **About the Creator**

**Ranjan Kumar** ([@rootranjan](https://github.com/rootranjan)) is a **Security Engineer** specializing in API security and attack surface management. With expertise in modern web frameworks and microservice architectures, Ranjan developed EndPointHawk to address the critical gap in automated API security discovery.

**Contact & Support:**
- **📧 Email**: rootranjan+endpointhawk@gmail.com
- **💬 GitHub Issues**: [Create an issue](https://github.com/rootranjan/endpointhawk/issues) for support
- **🔒 Security Reports**: [SECURITY.md](SECURITY.md) for vulnerability disclosure

---

## 🙏 **Acknowledgments**

**EndPointHawk wouldn't be possible without:**
- **🔒 OWASP Community** - For API security research and best practices
- **🛠️ Framework Developers** - For creating the amazing frameworks we secure
- **🧪 Security Researchers** - For vulnerability research and attack patterns
- **💡 Open Source Contributors** - For continuous improvements and feedback
- **🏢 Enterprise Users** - For real-world testing and feature requests

---

## 🚨 **Security Disclosure**

Found a security vulnerability in EndPointHawk? Please report it privately to [@rootranjan](https://github.com/rootranjan) before public disclosure. See [SECURITY.md](SECURITY.md) for our security policy.

---

## 🔗 **CI/CD Pipeline Integration**

EndPointHawk integrates seamlessly with your CI/CD pipeline to provide automated API security scanning. Here are practical examples for different platforms:

### **🚀 GitHub Actions**

```yaml
# .github/workflows/api-security-scan.yml
name: API Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  api-security:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0  # Full history for git comparison
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install EndPointHawk
      run: |
        git clone https://github.com/rootranjan/endpointhawk.git
        cd endpointhawk
        pip install -r requirements.txt
    
    - name: Run API Security Scan
      run: |
        cd endpointhawk
        python3 endpointhawk.py \
          --repo-path ../ \
          --frameworks auto \
          --use-ai \
          --risk-threshold medium \
          --output-format json,sarif \
          --output-dir ./security-reports
    
    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: endpointhawk/security-reports/endpointhawk_report.sarif
    
    - name: Comment PR with findings
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const report = JSON.parse(fs.readFileSync('endpointhawk/security-reports/endpointhawk_report.json', 'utf8'));
          
          const highRiskRoutes = report.routes.filter(r => r.risk_score >= 70);
          const mediumRiskRoutes = report.routes.filter(r => r.risk_score >= 40 && r.risk_score < 70);
          
          let comment = `## 🦅 EndPointHawk Security Scan Results\n\n`;
          comment += `**Total Routes Scanned:** ${report.total_routes}\n`;
          comment += `**High Risk Routes:** ${highRiskRoutes.length}\n`;
          comment += `**Medium Risk Routes:** ${mediumRiskRoutes.length}\n\n`;
          
          if (highRiskRoutes.length > 0) {
            comment += `### 🚨 High Risk Routes Found:\n`;
            highRiskRoutes.forEach(route => {
              comment += `- \`${route.method} ${route.path}\` (Risk: ${route.risk_score})\n`;
            });
            comment += `\n⚠️ **Please review these high-risk endpoints before merging.**\n`;
          }
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
```

### **🔧 GitLab CI**

```yaml
# .gitlab-ci.yml
stages:
  - security

api-security-scan:
  stage: security
  image: python:3.9-slim
  before_script:
    - apt-get update && apt-get install -y git
    - git clone https://github.com/rootranjan/endpointhawk.git
    - cd endpointhawk
    - pip install -r requirements.txt
  script:
    - python3 endpointhawk.py \
        --repo-path ../ \
        --frameworks auto \
        --use-ai \
        --risk-threshold medium \
        --output-format json,html \
        --output-dir ./security-reports
  artifacts:
    reports:
      security: endpointhawk/security-reports/endpointhawk_report.json
    paths:
      - endpointhawk/security-reports/
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### **⚡ Jenkins Pipeline**

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    stages {
        stage('API Security Scan') {
            steps {
                script {
                    // Checkout code
                    checkout scm
                    
                    // Install EndPointHawk
                    sh '''
                        git clone https://github.com/rootranjan/endpointhawk.git
                        cd endpointhawk
                        pip install -r requirements.txt
                    '''
                    
                    // Run security scan
                    sh '''
                        cd endpointhawk
                        python3 endpointhawk.py \
                            --repo-path ../ \
                            --frameworks auto \
                            --use-ai \
                            --risk-threshold high \
                            --output-format json,sarif,html \
                            --output-dir ./security-reports
                    '''
                    
                    // Archive results
                    archiveArtifacts artifacts: 'endpointhawk/security-reports/**/*'
                    
                    // Parse results for pipeline decision
                    def report = readJSON file: 'endpointhawk/security-reports/endpointhawk_report.json'
                    def highRiskCount = report.routes.count { it.risk_score >= 70 }
                    
                    if (highRiskCount > 0) {
                        error "Found ${highRiskCount} high-risk API endpoints. Pipeline blocked for security review."
                    }
                }
            }
        }
    }
    
    post {
        always {
            // Publish security report
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'endpointhawk/security-reports',
                reportFiles: 'endpointhawk_report.html',
                reportName: 'API Security Report'
            ])
        }
    }
}
```

### **☸️ Kubernetes/ArgoCD**

```yaml
# api-security-scan-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: api-security-scan
spec:
  template:
    spec:
      containers:
      - name: endpointhawk
        image: python:3.9-slim
        command:
        - /bin/bash
        - -c
        - |
          apt-get update && apt-get install -y git
          git clone https://github.com/rootranjan/endpointhawk.git
          cd endpointhawk
          pip install -r requirements.txt
          
          # Clone your repository
          git clone $REPO_URL /workspace
          cd /workspace
          
          # Run security scan
          cd ../endpointhawk
          python3 endpointhawk.py \
            --repo-path /workspace \
            --frameworks auto \
            --use-ai \
            --risk-threshold medium \
            --output-format json,html \
            --output-dir ./security-reports
          
          # Upload results to artifact storage
          # (Configure based on your setup)
        env:
        - name: REPO_URL
          value: "https://github.com/your-org/your-repo.git"
        - name: GEMINI_API_KEY
          valueFrom:
            secretKeyRef:
              name: endpointhawk-secrets
              key: gemini-api-key
      restartPolicy: Never
  backoffLimit: 3
```

### **🔍 Advanced CI/CD Features**

#### **Git Comparison in CI/CD**
```bash
# Compare against previous release
python3 endpointhawk.py \
  --repo-path . \
  --compare-tags v1.0.0,v1.1.0 \
  --risk-analysis \
  --output-format json,sarif

# Compare against main branch
python3 endpointhawk.py \
  --repo-path . \
  --compare-branches main,feature/new-api \
  --include-file-changes \
  --output-format json
```

#### **Performance Optimization for CI/CD**
```bash
# Fast scanning for CI/CD environments
python3 endpointhawk.py \
  --repo-path . \
  --performance-mode fast \
  --cache-enabled \
  --max-workers 4 \
  --max-memory 512 \
  --output-format json
```

#### **Enterprise Configuration**
```bash
# Use enterprise configuration
python3 endpointhawk.py \
  --repo-path . \
  --config enterprise-config.yaml \
  --enterprise-report security \
  --output-format html,json,sarif
```

### **📊 CI/CD Best Practices**

1. **Scan on every PR** - Catch security issues before merging
2. **Block high-risk findings** - Fail pipeline for critical vulnerabilities
3. **Generate SARIF reports** - Integrate with security tools
4. **Use caching** - Speed up repeated scans
5. **Set appropriate thresholds** - Balance security vs. development speed
6. **Archive reports** - Keep historical security data
7. **Notify security team** - Alert on critical findings

### **🔐 Security Considerations**

- **API Keys**: Store `GEMINI_API_KEY` as CI/CD secrets
- **Repository Access**: Use appropriate authentication for private repos
- **Output Security**: Don't expose sensitive findings in public logs
- **Rate Limiting**: Respect API limits in CI/CD environments

---

## 🐳 **Docker Deployment**

EndPointHawk is optimized for Docker deployment, making it perfect for scanning multiple repositories across different environments.

### **🚀 Quick Docker Start**

```bash
# Build the Docker image
docker build -t endpointhawk:latest .

# Run a quick scan
docker run --rm -v $(pwd):/workspace endpointhawk:latest \
  --repo-path /workspace \
  --frameworks auto \
  --output-format json,html
```

### **📦 Multi-Repository Setup**

#### **Option 1: Docker Compose (Recommended)**

```bash
# Create directory structure
mkdir -p repos reports cache config

# Clone your repositories
git clone https://github.com/your-org/api-service.git repos/api-service
git clone https://github.com/your-org/user-service.git repos/user-service
git clone https://github.com/your-org/payment-service.git repos/payment-service

# Run CLI scan
docker-compose --profile cli up endpointhawk-cli

# Run web interface
docker-compose --profile web up endpointhawk-web
```

#### **Option 2: Batch Scanning**

```json
# batch-config.json
{
  "repositories": [
    {
      "name": "api-service",
      "url": "https://github.com/your-org/api-service.git",
      "branch": "main",
      "frameworks": ["nestjs", "express"]
    },
    {
      "name": "user-service", 
      "url": "https://github.com/your-org/user-service.git",
      "branch": "develop",
      "frameworks": ["fastapi", "django"]
    },
    {
      "name": "payment-service",
      "url": "https://github.com/your-org/payment-service.git", 
      "branch": "main",
      "frameworks": ["spring", "go"]
    }
  ],
  "scan_config": {
    "risk_threshold": "high",
    "use_ai": true,
    "output_formats": ["json", "html", "sarif"]
  }
}
```

```bash
# Run batch scan
docker-compose --profile batch up endpointhawk-batch
```

#### **Option 3: Scheduled Scanning**

```bash
# Run scheduled scans (daily at 2 AM)
docker-compose --profile scheduler up endpointhawk-scheduler

# Custom schedule (every 6 hours)
SCAN_SCHEDULE="0 */6 * * *" docker-compose --profile scheduler up endpointhawk-scheduler
```

### **🔧 Docker Configuration**

#### **Environment Variables**

```bash
# .env file
GEMINI_API_KEY=your_gemini_api_key_here
SECRET_KEY=your_secret_key_here
SCAN_SCHEDULE=0 2 * * *  # Daily at 2 AM
```

#### **Volume Mounts**

```bash
# Mount repositories
-v ./repos:/workspace:ro

# Mount reports output
-v ./reports:/reports

# Mount cache for performance
-v ./cache:/cache

# Mount custom configurations
-v ./config:/app/config:ro
```

### **⚡ Performance Optimized Docker**

#### **Fast Scanning Mode**
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -v ./reports:/reports \
  -v ./cache:/cache \
  endpointhawk:latest \
  --repo-path /workspace \
  --performance-mode fast \
  --max-workers 4 \
  --max-memory 512 \
  --cache-enabled \
  --output-format json
```

#### **Memory Optimized Mode**
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -v ./reports:/reports \
  -v ./cache:/cache \
  --memory=1g \
  endpointhawk:latest \
  --repo-path /workspace \
  --performance-mode memory-optimized \
  --max-memory 512 \
  --output-format json
```

### **🌐 Enterprise Docker Deployment**

#### **Kubernetes Deployment**

```yaml
# endpointhawk-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: endpointhawk
spec:
  replicas: 1
  selector:
    matchLabels:
      app: endpointhawk
  template:
    metadata:
      labels:
        app: endpointhawk
    spec:
      containers:
      - name: endpointhawk
        image: endpointhawk:latest
        env:
        - name: GEMINI_API_KEY
          valueFrom:
            secretKeyRef:
              name: endpointhawk-secrets
              key: gemini-api-key
        volumeMounts:
        - name: repos
          mountPath: /workspace
          readOnly: true
        - name: reports
          mountPath: /reports
        - name: cache
          mountPath: /cache
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: repos
        persistentVolumeClaim:
          claimName: repos-pvc
      - name: reports
        persistentVolumeClaim:
          claimName: reports-pvc
      - name: cache
        persistentVolumeClaim:
          claimName: cache-pvc
```

#### **Docker Swarm**

```bash
# Deploy to Docker Swarm
docker stack deploy -c docker-compose.yml endpointhawk

# Scale services
docker service scale endpointhawk_endpointhawk-cli=3
```

### **🔍 Docker Best Practices**

#### **Security**
- ✅ **Non-root user** - Container runs as `endpointhawk` user
- ✅ **Read-only mounts** - Repository mounts are read-only
- ✅ **Secrets management** - Use Docker secrets for API keys
- ✅ **Resource limits** - Set memory and CPU limits

#### **Performance**
- ✅ **Multi-stage builds** - Optimized image size
- ✅ **Volume caching** - Persistent cache across runs
- ✅ **Parallel scanning** - Multiple workers for large repos
- ✅ **Health checks** - Container health monitoring

#### **Monitoring**
```bash
# Check container health
docker ps --filter "name=endpointhawk"

# View logs
docker logs endpointhawk-cli

# Monitor resource usage
docker stats endpointhawk-cli
```

### **📊 Docker Usage Examples**

#### **Single Repository Scan**
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -v ./reports:/reports \
  endpointhawk:latest \
  --repo-path /workspace \
  --frameworks auto \
  --use-ai \
  --risk-threshold high \
  --output-format json,html,sarif
```

#### **Multiple Repositories**
```bash
# Scan all repos in directory
for repo in repos/*; do
  docker run --rm \
    -v $(pwd)/$repo:/workspace \
    -v ./reports:/reports \
    -v ./cache:/cache \
    endpointhawk:latest \
    --repo-path /workspace \
    --frameworks auto \
    --output-format json,html
done
```

#### **CI/CD Integration**
```bash
# In your CI/CD pipeline
docker run --rm \
  -v $CI_PROJECT_DIR:/workspace \
  -v $CI_PROJECT_DIR/reports:/reports \
  endpointhawk:latest \
  --repo-path /workspace \
  --frameworks auto \
  --risk-threshold medium \
  --output-format json,sarif
```

---

**🦅 EndPointHawk - Securing APIs, one route at a time**

*Built with ❤️ by the security community* 