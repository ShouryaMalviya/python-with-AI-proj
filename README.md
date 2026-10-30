# 🛡️ CodeGuard Lite — Automated Code Reviewer & Security Scanner

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask 3.x](https://img.shields.io/badge/Framework-Flask_3.x-green.svg)](https://flask.palletsprojects.com/)
[![AST Engine](https://img.shields.io/badge/Engine-Python_AST_(Zero_Execution)-00ff88.svg)](https://docs.python.org/3/library/ast.html)
[![Security Policy](https://img.shields.io/badge/Security-Safe_Static_Analysis-critical.svg)](#security-architecture)

> **CodeGuard Lite** is a modern, high-performance web application designed for automated static code review and security scanning of Python source files. Powered by Python's native **Abstract Syntax Tree (AST)** module, it inspects code for critical vulnerabilities, dangerous dynamic executions, and PEP compliance omissions with **zero execution risk**.

---

## ⚡ Key Highlights

* **100% Zero-Execution Risk:** Source files are parsed purely into AST nodes without importing, compiling, or executing untrusted code.
* **Modern Cybersecurity Dashboard:** Dark theme, deep emerald green accents, neon green highlights, glassmorphism cards, and fluid animations.
* **Native CPython AST Engine:** Sub-millisecond parsing latency using Python's built-in `ast` standard library module.
* **Dual Ingestion Methods:** Drag-and-drop `.py` file uploads or paste Python code directly into the browser editor.
* **Real-time Cyber Scanning Animation:** Visual progress feedback breaking down each AST inspection phase.
* **Instant Markdown Audit Reports:** Export comprehensive `.md` compliance reports containing executive summaries, metrics, and remediation guidance with a single click.

---

## 🔍 Built-In Security & Quality Rules

| # | Rule Name | AST Target | Severity | Impact & Remediation |
|---|---|---|---|---|
| **1** | **Dangerous `eval()` Call** | `ast.Call` where `func == 'eval'` | 🔴 **Critical** | Prevents arbitrary code execution (CWE-95). Replaces with `ast.literal_eval()` or structured JSON parsing. |
| **2** | **Dangerous `exec()` Call** | `ast.Call` where `func == 'exec'` | 🔴 **Critical** | Prevents dynamic code injection and execution of untrusted multi-statement strings. |
| **3** | **Wildcard Imports (`*`)** | `ast.ImportFrom` with alias `'*'` | 🟡 **Warning** | Eliminates namespace pollution and variable shadowing per PEP 8 guidelines. |
| **4** | **Missing Function Docstrings** | `ast.FunctionDef` (public) | 🔵 **Info** | Flags public functions missing docstrings per PEP 257 standards. |
| **5** | **Missing Class Docstrings** | `ast.ClassDef` (public) | 🔵 **Info** | Flags public classes missing architectural docstrings per PEP 257 standards. |
| **6** | **Python Syntax Errors** | `SyntaxError` exception capture | 🔴 **Critical** | Traps syntax errors safely with exact line, offset, and human-friendly troubleshooting advice. |

---

## 📁 Project Directory Structure

```text
CodeGuard-Lite/
│
├── app.py                  # Main Flask application and routing controller
├── analyzer.py             # Pure AST static code review and security engine
├── requirements.txt        # Lightweight dependencies (Flask & Werkzeug)
│
├── templates/
│   ├── index.html          # Cyber Home Dashboard & file scanner dropzone
│   └── results.html        # Interactive Audit Results & code inspector
│
├── static/
│   ├── css/
│   │   └── style.css       # Custom glassmorphism, dark emerald & neon theme
│   └── js/
│       └── script.js       # Drag-and-drop, scan progress bar, and filters
│
└── README.md               # Complete project documentation
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
* Python 3.10 or higher.
* `pip` package manager.

### 2. Install Dependencies
Run the following command in your terminal:

```bash
pip install -r requirements.txt
```

### 3. Launch the Application
Start the Flask development server:

```bash
python app.py
```

### 4. Open in Browser
Navigate to the following URL in any modern browser:

```text
http://127.0.0.1:5000
```

---

## 🧪 Testing & Verification

CodeGuard Lite includes built-in verification mechanisms:

1. **One-Click Sample File:** Click **"Try Live Sample File"** on the home page or **"Load Sample Vulnerable Code"** in the scanner. This automatically loads a script with intentional security vulnerabilities (`eval`, `exec`, wildcard imports, and missing docstrings) to immediately observe the scanner in action.
2. **File Upload Testing:** Drag-and-drop any Python `.py` file to test static analysis.
3. **Downloadable Markdown Report:** After scanning, click **"Download Markdown Report (.md)"** on the results page to download the full audit report.
4. **Automated Unit Tests:** Execute the test suite using standard `unittest`:
   ```bash
   python test_suite.py
   ```

---

## 🔒 Security Architecture

1. **Zero Execution Guarantee:** CodeGuard Lite never invokes `exec()`, `eval()`, `__import__()`, or `subprocess` on uploaded files.
2. **Safe Memory Processing:** Uploaded files are read into memory, decoded with fallback handling, and passed strictly to `ast.parse()`.
3. **Payload Size Guard:** Uploads exceeding 2MB are automatically rejected with an HTTP 413 error to protect against memory exhaustion.
4. **Path Sanitization:** File names are sanitized using `werkzeug.utils.secure_filename` to prevent path traversal.

---

## 📄 License

MIT License &copy; 2026 CodeGuard Lite. Built for developers prioritizing code security and quality.

