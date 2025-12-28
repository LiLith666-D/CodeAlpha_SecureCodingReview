# CodeAlpha_SecureCodingReview – Secure Coding Review Using Bandit

---

## Overview

This project demonstrates a **Secure Coding Review** of a Python-based web application using **static code analysis and manual inspection**. The objective is to identify common security vulnerabilities, analyze their impact, and implement secure coding best practices to mitigate them.

The project is developed as part of the **CodeAlpha Cyber Security Internship – Task 3** and showcases a real-world secure coding workflow by comparing an intentionally vulnerable application with a hardened secure implementation.

---

## Objectives

- Identify common software security vulnerabilities
- Perform static code analysis using Bandit
- Understand insecure coding patterns
- Apply secure coding best practices
- Validate fixes through re-scanning
- Compare vulnerable and secure implementations

---

## Features

- Intentionally vulnerable Python web application
- Fully secured and hardened application
- Static Application Security Testing (SAST)
- Detection of:
  - Hardcoded secrets
  - SQL Injection
  - Command Injection
  - Insecure deserialization
  - Broken authentication and authorization
  - Debug mode exposure
- Clean project structure
- Bandit scan reports for validation

---

## Technologies Used

- Python 3
- Flask Framework
- SQLite Database
- Bandit (Static Security Analyzer)
- Linux (Kali Linux)
- Werkzeug (Password hashing)


---

## Configuration Highlights

- Secret keys managed securely using configuration files
- Parameterized SQL queries to prevent injection
- Removal of unsafe modules (`subprocess`, `pickle`)
- Secure password hashing and verification
- Debug mode disabled in secure version
- Logging enabled for authentication events

---

## How to Execute

### 1. Create Virtual Environment

```python3 -m venv venv```
```source venv/bin/activate```


### 2. Install Dependencies

```pip install -r requirements.txt```

### 3. Run Vulnerable Application (For Analysis Only)

```python3 app/appVul.py```

### 4. Run Secure Application

```python3 app/appSec.py```

---

## Static Analysis Using Bandit

### Scan Vulnerable Code

```bandit -r app/appVul.py > reports/bandit_report_vul.txt```

### Scan Secure Code

```bandit -r app/appSec.py > reports/bandit_report_sec.txt```

---

## Results Observed

### Vulnerable Code Scan

* Multiple security issues detected
* Low, Medium, and High severity vulnerabilities
* Confirms presence of insecure coding patterns

### Secure Code Scan

* No issues identified
* All previously detected vulnerabilities mitigated
* Secure coding best practices successfully implemented

---

## Testing Performed

* Static code analysis using Bandit
* Manual inspection of authentication logic
* Verification of SQL injection mitigation
* Validation of secret key handling
* Comparison of before-and-after security posture

All vulnerabilities were successfully detected and resolved.

---

## Security Note

The vulnerable application is intentionally insecure and is provided strictly for learning and demonstration purposes. It must never be deployed in a production environment.

---

## Learning Outcomes

* Hands-on experience with secure coding review
* Understanding common software vulnerabilities
* Practical use of static security analysis tools
* Implementing industry-recommended secure coding practices
* Interpreting security scan reports

---

## Author

Dheekshita R

Cyber Security Intern – CodeAlpha

---

## Conclusion

This project demonstrates a complete secure coding review lifecycle by analyzing vulnerable source code, identifying security flaws, applying secure coding practices, and validating fixes through static analysis. The secure implementation successfully eliminates all detected vulnerabilities, reinforcing the importance of proactive security in software development.



