"""
CodeGuard Lite — Automated Code Reviewer & Security Scanner
Core AST Static Code Analysis Engine

This module performs pure static analysis on Python source code using Python's
built-in `ast` module. The source code is NEVER executed or imported dynamically,
guaranteeing 100% safe analysis of untrusted files.
"""

import ast
import datetime
from typing import Dict, List, Any, Optional


class CodeAnalyzer:
    """
    Static Code Analyzer powered by Python's built-in Abstract Syntax Tree (AST).
    
    Detects:
    1. eval() usage (Critical) - CWE-95 Arbitrary Code Execution
    2. exec() usage (Critical) - CWE-95 Dynamic Code Execution
    3. Wildcard imports (Warning) - PEP 8 / Namespace Pollution
    4. Missing public function docstrings (Info) - PEP 257 Violation
    5. Missing public class docstrings (Info) - PEP 257 Violation
    6. Python syntax errors (Critical) - Invalid Python Syntax
    """

    def __init__(self, source_code: str, filename: str = "uploaded_file.py"):
        self.source_code = source_code or ""
        self.filename = filename
        self.lines = self.source_code.splitlines()
        self.issues: List[Dict[str, Any]] = []
        self.stats = {
            "total_lines": len(self.lines),
            "code_lines": 0,
            "comment_lines": 0,
            "blank_lines": 0,
            "function_count": 0,
            "class_count": 0,
        }
        self.syntax_valid = True
        self._calculate_line_stats()

    def _calculate_line_stats(self) -> None:
        """Compute basic line statistics without executing code."""
        for line in self.lines:
            stripped = line.strip()
            if not stripped:
                self.stats["blank_lines"] += 1
            elif stripped.startswith("#"):
                self.stats["comment_lines"] += 1
            else:
                self.stats["code_lines"] += 1

    def _get_snippet(self, lineno: int) -> str:
        """Retrieve the exact code snippet for a specific line number."""
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1]
        return ""

    def _is_call_to(self, node: ast.Call, target_name: str) -> bool:
        """
        Check if an ast.Call node invokes the specified function name.
        Handles direct calls: eval(...) and builtins calls: builtins.eval(...)
        """
        func = node.func
        # Direct call: eval(...) or exec(...)
        if isinstance(func, ast.Name) and func.id == target_name:
            return True
        # Attribute call: builtins.eval(...)
        if isinstance(func, ast.Attribute) and func.attr == target_name:
            if isinstance(func.value, ast.Name) and func.value.id in ("builtins", "__builtins__"):
                return True
        return False

    def analyze(self) -> Dict[str, Any]:
        """
        Parse source code with AST and execute security and style rules.
        Never executes source code.
        """
        self.issues.clear()
        
        # Check for empty file
        if not self.source_code.strip():
            return self._build_result_dict()

        # Step 1: Parse AST and handle Syntax Errors
        try:
            tree = ast.parse(self.source_code, filename=self.filename)
        except SyntaxError as exc:
            self.syntax_valid = False
            snippet = exc.text.rstrip() if exc.text else self._get_snippet(exc.lineno or 1)
            self.issues.append({
                "id": "ERR_SYNTAX",
                "severity": "critical",
                "category": "Syntax Error",
                "title": "Python Syntax Error Detected",
                "line": exc.lineno or 1,
                "col": exc.offset or 1,
                "description": f"The file contains invalid Python syntax: {exc.msg}",
                "snippet": snippet,
                "recommendation": (
                    "Inspect the indicated line for syntax mistakes such as missing colons (:), "
                    "unbalanced parentheses/brackets, mismatched quotes, or indentation errors."
                )
            })
            return self._build_result_dict()

        # Step 2: Traverse AST for security vulnerabilities and code quality rules
        self._inspect_ast(tree)

        return self._build_result_dict()

    def _inspect_ast(self, tree: ast.AST) -> None:
        """Inspect all nodes in the parsed Abstract Syntax Tree."""
        for node in ast.walk(tree):
            # Check 1: Dangerous eval() usage (Critical)
            if isinstance(node, ast.Call) and self._is_call_to(node, "eval"):
                self.issues.append({
                    "id": "SEC_EVAL",
                    "severity": "critical",
                    "category": "Security Vulnerability",
                    "title": "Dangerous 'eval()' Execution",
                    "line": getattr(node, "lineno", 1),
                    "col": getattr(node, "col_offset", 0),
                    "snippet": self._get_snippet(getattr(node, "lineno", 1)),
                    "description": (
                        "The 'eval()' function evaluates arbitrary Python code strings dynamically. "
                        "If user-supplied or untrusted input reaches 'eval()', an attacker can execute "
                        "arbitrary code on the host system (CWE-95 Remote Code Execution)."
                    ),
                    "recommendation": (
                        "Replace 'eval()' with safe alternatives such as 'ast.literal_eval()' for safely parsing "
                        "Python literals, 'json.loads()' for structured data, or an explicit mapping/parser."
                    )
                })

            # Check 2: Dangerous exec() usage (Critical)
            elif isinstance(node, ast.Call) and self._is_call_to(node, "exec"):
                self.issues.append({
                    "id": "SEC_EXEC",
                    "severity": "critical",
                    "category": "Security Vulnerability",
                    "title": "Dangerous 'exec()' Execution",
                    "line": getattr(node, "lineno", 1),
                    "col": getattr(node, "col_offset", 0),
                    "snippet": self._get_snippet(getattr(node, "lineno", 1)),
                    "description": (
                        "The 'exec()' function dynamically executes multi-statement Python code strings. "
                        "This introduces severe code injection vulnerabilities, circumvents static security "
                        "guarantees, and makes code debugging and optimization unpredictable."
                    ),
                    "recommendation": (
                        "Avoid dynamic statement execution. Refactor code to use standard functions, "
                        "polymorphism, or dedicated domain-specific safe configuration parsers."
                    )
                })

            # Check 3: Wildcard imports (Warning)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        module_name = node.module or "module"
                        self.issues.append({
                            "id": "STYLE_WILDCARD_IMPORT",
                            "severity": "warning",
                            "category": "Code Quality",
                            "title": f"Wildcard Import from '{module_name}'",
                            "line": getattr(node, "lineno", 1),
                            "col": getattr(node, "col_offset", 0),
                            "snippet": self._get_snippet(getattr(node, "lineno", 1)),
                            "description": (
                                f"Wildcard import 'from {module_name} import *' pollutes the local namespace, "
                                "causes unintentional variable shadowing, masks undefined names from static "
                                "checkers, and violates PEP 8 guidelines."
                            ),
                            "recommendation": (
                                f"Explicitly import only the required symbols (e.g., 'from {module_name} import foo, bar') "
                                f"or import the module directly ('import {module_name}')."
                            )
                        })

            # Check 4: Missing public function docstrings (Info)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.stats["function_count"] += 1
                # Only check public functions (not starting with '_')
                if not node.name.startswith("_"):
                    docstring = ast.get_docstring(node)
                    if not docstring or not docstring.strip():
                        self.issues.append({
                            "id": "DOC_MISSING_FUNC",
                            "severity": "info",
                            "category": "Documentation",
                            "title": f"Missing Docstring in Public Function '{node.name}'",
                            "line": getattr(node, "lineno", 1),
                            "col": getattr(node, "col_offset", 0),
                            "snippet": self._get_snippet(getattr(node, "lineno", 1)),
                            "description": (
                                f"The public function '{node.name}()' does not contain a docstring. "
                                "Public APIs should document their purpose, arguments, return types, "
                                "and potential exceptions per PEP 257."
                            ),
                            "recommendation": (
                                f"Add a PEP 257 compliant docstring at the top of '{node.name}()':\n"
                                f'"""Explain what {node.name} does, its parameters, and return value."""'
                            )
                        })

            # Check 5: Missing public class docstrings (Info)
            elif isinstance(node, ast.ClassDef):
                self.stats["class_count"] += 1
                # Only check public classes (not starting with '_')
                if not node.name.startswith("_"):
                    docstring = ast.get_docstring(node)
                    if not docstring or not docstring.strip():
                        self.issues.append({
                            "id": "DOC_MISSING_CLASS",
                            "severity": "info",
                            "category": "Documentation",
                            "title": f"Missing Docstring in Public Class '{node.name}'",
                            "line": getattr(node, "lineno", 1),
                            "col": getattr(node, "col_offset", 0),
                            "snippet": self._get_snippet(getattr(node, "lineno", 1)),
                            "description": (
                                f"The public class '{node.name}' lacks a class-level docstring. "
                                "Classes should clearly state their architectural responsibility and public attributes."
                            ),
                            "recommendation": (
                                f"Add a class docstring immediately below 'class {node.name}:':\n"
                                f'"""Summary of {node.name}\'s responsibility and public interface."""'
                            )
                        })

        # Sort issues by line number then column
        self.issues.sort(key=lambda x: (x["line"], x["col"]))

    def _calculate_score(self, critical_cnt: int, warning_cnt: int, info_cnt: int) -> int:
        """
        Calculate health score from 0 to 100 based on severity deductions.
        Critical: -25 pts
        Warning: -10 pts
        Info: -3 pts
        """
        if not self.syntax_valid:
            return 0
        score = 100 - (critical_cnt * 25 + warning_cnt * 10 + info_cnt * 3)
        return max(0, min(100, score))

    def _get_grade(self, score: int) -> str:
        """Compute letter grade from health score."""
        if score >= 95:
            return "A+"
        elif score >= 85:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 45:
            return "D"
        else:
            return "F"

    def _build_result_dict(self) -> Dict[str, Any]:
        """Aggregate all metrics and issues into a structured result dictionary."""
        critical_cnt = sum(1 for i in self.issues if i["severity"] == "critical")
        warning_cnt = sum(1 for i in self.issues if i["severity"] == "warning")
        info_cnt = sum(1 for i in self.issues if i["severity"] == "info")
        total_issues = len(self.issues)
        score = self._calculate_score(critical_cnt, warning_cnt, info_cnt)
        grade = self._get_grade(score)

        return {
            "filename": self.filename,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stats": self.stats,
            "summary": {
                "total_issues": total_issues,
                "critical": critical_cnt,
                "warnings": warning_cnt,
                "info": info_cnt,
                "score": score,
                "grade": grade,
                "syntax_valid": self.syntax_valid,
            },
            "issues": self.issues,
        }


def generate_markdown_report(analysis_results: Dict[str, Any], source_code: str = "") -> str:
    """
    Generate a professional, downloadable Markdown report summarizing the code audit.
    """
    summary = analysis_results.get("summary", {})
    stats = analysis_results.get("stats", {})
    issues = analysis_results.get("issues", [])
    filename = analysis_results.get("filename", "unknown.py")
    timestamp = analysis_results.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    status_icon = "🟢 PASS" if summary.get("critical", 0) == 0 and summary.get("warnings", 0) == 0 else "🔴 ACTION REQUIRED"
    if summary.get("critical", 0) == 0 and summary.get("warnings", 0) > 0:
        status_icon = "🟡 REVIEW SUGGESTED"

    md = []
    md.append(f"# 🛡️ CodeGuard Lite — Security & Quality Audit Report")
    md.append("")
    md.append(f"> **Automated Static Code Analysis** performed on `{filename}` at `{timestamp}`.")
    md.append("")
    md.append("---")
    md.append("")
    md.append("## 📊 Executive Summary")
    md.append("")
    md.append(f"| Metric | Value | Status |")
    md.append(f"| :--- | :--- | :--- |")
    md.append(f"| **Target File** | `{filename}` | - |")
    md.append(f"| **Overall Health Score** | **{summary.get('score', 0)} / 100** (Grade `{summary.get('grade', 'F')}`) | {status_icon} |")
    md.append(f"| **Total Lines Scanned** | `{stats.get('total_lines', 0)}` lines (`{stats.get('code_lines', 0)}` code, `{stats.get('comment_lines', 0)}` comments) | - |")
    md.append(f"| **Total Issues Detected** | **{summary.get('total_issues', 0)}** | - |")
    md.append(f"| **Critical Vulnerabilities** | **{summary.get('critical', 0)}** | {'🔴 Needs Immediate Fix' if summary.get('critical', 0) > 0 else '🟢 Zero Detected'} |")
    md.append(f"| **Warnings (Code Smells)** | **{summary.get('warnings', 0)}** | {'🟡 Attention Recommended' if summary.get('warnings', 0) > 0 else '🟢 Clean'} |")
    md.append(f"| **Informational (PEP 257)** | **{summary.get('info', 0)}** | {'🔵 Best Practice Note' if summary.get('info', 0) > 0 else '🟢 Documented'} |")
    md.append("")
    md.append("---")
    md.append("")
    md.append("## 🔍 Detailed Findings")
    md.append("")

    if not issues:
        md.append("### ✅ Clean Code Report")
        md.append("No security vulnerabilities, wildcard imports, missing docstrings, or syntax errors were identified.")
        md.append("Your code adheres to all CodeGuard Lite security policies!")
    else:
        for idx, issue in enumerate(issues, start=1):
            severity = issue.get("severity", "info").upper()
            badge = "🔴 CRITICAL" if severity == "CRITICAL" else ("🟡 WARNING" if severity == "WARNING" else "🔵 INFO")
            title = issue.get("title", "Issue")
            line = issue.get("line", 1)
            col = issue.get("col", 0)
            desc = issue.get("description", "")
            snippet = issue.get("snippet", "")
            rec = issue.get("recommendation", "")

            md.append(f"### {idx}. [{badge}] {title} — Line {line}")
            md.append(f"- **Severity:** `{severity}`")
            md.append(f"- **Category:** `{issue.get('category', 'General')}`")
            md.append(f"- **Location:** Line `{line}`, Column `{col}`")
            md.append("")
            md.append(f"**Description:**")
            md.append(f"{desc}")
            md.append("")
            if snippet:
                md.append(f"**Offending Code Snippet:**")
                md.append("```python")
                md.append(snippet)
                md.append("```")
                md.append("")
            md.append(f"**Recommended Remediation:**")
            md.append(f"{rec}")
            md.append("")
            md.append("---")
            md.append("")

    md.append("## 🛡️ About CodeGuard Lite")
    md.append("")
    md.append("CodeGuard Lite is an automated static code analysis engine that inspects Python code using the")
    md.append("built-in Abstract Syntax Tree (`ast`). Source files are **never executed**, ensuring zero-risk analysis.")
    md.append("")
    md.append("*Report generated automatically by CodeGuard Lite.*")

    return "\n".join(md)
