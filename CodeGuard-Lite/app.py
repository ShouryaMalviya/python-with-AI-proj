"""
CodeGuard Lite — Automated Code Reviewer & Security Scanner
Main Flask Application Server
"""

import io
import os
import uuid
import datetime
from typing import Dict, Any
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    send_file,
    abort,
)
from werkzeug.utils import secure_filename

from analyzer import CodeAnalyzer, generate_markdown_report

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "codeguard-lite-secure-ast-key-2026")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 Megabytes max

# In-memory scan store (scan_id -> { results, source_code, filename, report_md })
SCAN_STORE: Dict[str, Dict[str, Any]] = {}
MAX_STORED_SCANS = 100

ALLOWED_EXTENSIONS = {"py"}

SAMPLE_VULNERABLE_CODE = '''"""
Sample Service Module with Intentional Security & Quality Issues
Test script designed for CodeGuard Lite AST static verification.
"""

from math import *
import os

class DatabaseConnector:
    # Notice: Missing class docstring (PEP 257)
    def __init__(self, host: str):
        self.host = host

    def run_query(self, query_string: str):
        # Notice: Missing method docstring (PEP 257)
        # Critical: Dangerous exec execution
        exec(f"db_cache_{self.host} = '{query_string}'")
        return True


def calculate_dynamic_expression(user_payload: str):
    # Notice: Missing public function docstring (PEP 257)
    # Critical: Dangerous eval execution of untrusted input
    sanitized = user_payload.strip()
    result = eval(sanitized)
    return result


def safe_square(n: int) -> int:
    """Safely compute the square of an integer (Compliant with PEP 257)."""
    return n * n
'''


def allowed_file(filename: str) -> bool:
    """Check if the uploaded file has an allowed extension (.py)."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def prune_scan_store():
    """Keep memory footprint bounded by trimming oldest scans if exceeding max."""
    global SCAN_STORE
    if len(SCAN_STORE) > MAX_STORED_SCANS:
        # Remove oldest 20 entries
        keys_to_remove = list(SCAN_STORE.keys())[:20]
        for k in keys_to_remove:
            SCAN_STORE.pop(k, None)


@app.route("/", methods=["GET"])
def index():
    """Render the modern Home Dashboard and Code Scanner landing page."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """
    Handle code analysis request.
    Accepts either an uploaded .py file or raw Python code string.
    Never executes source code.
    """
    source_code = ""
    filename = "uploaded_script.py"

    # Option 1: File Upload
    if "file" in request.files and request.files["file"].filename != "":
        uploaded_file = request.files["file"]
        raw_name = uploaded_file.filename or "unknown.py"
        
        if not allowed_file(raw_name):
            msg = "Invalid file type. Please upload a valid Python file (.py)."
            if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.form.get("ajax") == "1":
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "error")
            return redirect(url_for("index"))

        filename = secure_filename(raw_name)
        try:
            content_bytes = uploaded_file.read()
            # Try utf-8 first, fallback to latin-1
            try:
                source_code = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                source_code = content_bytes.decode("latin-1", errors="replace")
        except Exception as e:
            msg = f"Failed to read uploaded file: {str(e)}"
            if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.form.get("ajax") == "1":
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "error")
            return redirect(url_for("index"))

    # Option 2: Direct Code Paste
    elif "code" in request.form and request.form["code"].strip():
        source_code = request.form["code"]
        filename = request.form.get("filename_custom", "").strip() or "pasted_script.py"
        if not filename.endswith(".py"):
            filename += ".py"
        filename = secure_filename(filename)

    else:
        msg = "No Python code provided. Please upload a .py file or paste source code."
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.form.get("ajax") == "1":
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "error")
        return redirect(url_for("index"))

    # Perform Pure Static AST Analysis (Never executes code)
    analyzer = CodeAnalyzer(source_code=source_code, filename=filename)
    results = analyzer.analyze()
    markdown_report = generate_markdown_report(results, source_code)

    # Store result in memory
    scan_id = uuid.uuid4().hex[:12]
    prune_scan_store()
    SCAN_STORE[scan_id] = {
        "scan_id": scan_id,
        "filename": filename,
        "results": results,
        "source_code": source_code,
        "markdown_report": markdown_report,
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Return JSON for AJAX requests (powers the animated cyber progress bar)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.form.get("ajax") == "1":
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "redirect_url": url_for("view_results", scan_id=scan_id),
            "summary": results["summary"],
        })

    return redirect(url_for("view_results", scan_id=scan_id))


@app.route("/results/<scan_id>", methods=["GET"])
def view_results(scan_id: str):
    """Render the Results Dashboard for a completed scan."""
    scan_data = SCAN_STORE.get(scan_id)
    if not scan_data:
        flash("Scan session expired or not found. Please initiate a new scan.", "warning")
        return redirect(url_for("index"))

    results = scan_data["results"]
    source_lines = scan_data["source_code"].splitlines()
    
    # Map issue lines for highlighting in the source code inspector
    issues_by_line = {}
    for issue in results["issues"]:
        line_num = issue["line"]
        if line_num not in issues_by_line:
            issues_by_line[line_num] = []
        issues_by_line[line_num].append(issue)

    return render_template(
        "results.html",
        scan_id=scan_id,
        filename=scan_data["filename"],
        results=results,
        summary=results["summary"],
        stats=results["stats"],
        issues=results["issues"],
        source_lines=source_lines,
        issues_by_line=issues_by_line,
        timestamp=scan_data["created_at"],
    )


@app.route("/download-report/<scan_id>", methods=["GET"])
def download_report(scan_id: str):
    """Generate and deliver the downloadable Markdown report file."""
    scan_data = SCAN_STORE.get(scan_id)
    if not scan_data:
        flash("Report not found or session has expired.", "error")
        return redirect(url_for("index"))

    report_content = scan_data["markdown_report"]
    filename = scan_data["filename"].rsplit(".", 1)[0]
    download_filename = f"codeguard_report_{filename}.md"

    # Create in-memory file stream
    mem_file = io.BytesIO()
    mem_file.write(report_content.encode("utf-8"))
    mem_file.seek(0)

    return send_file(
        mem_file,
        mimetype="text/markdown",
        as_attachment=True,
        download_name=download_filename,
    )


@app.route("/api/sample-code", methods=["GET"])
def get_sample_code():
    """Provide realistic sample code with deliberate security flaws for immediate testing."""
    return jsonify({
        "success": True,
        "code": SAMPLE_VULNERABLE_CODE,
        "filename": "vulnerable_demo.py"
    })


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "CodeGuard Lite",
        "ast_engine": "active",
        "timestamp": datetime.datetime.now().isoformat()
    })


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle uploads exceeding maximum allowed size."""
    msg = "File exceeds the 2MB size limit. Please upload a smaller Python script."
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": False, "error": msg}), 413
    flash(msg, "error")
    return redirect(url_for("index"))


@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors."""
    return render_template("index.html"), 404


if __name__ == "__main__":
    # Run the server on http://127.0.0.1:5000
    print("\n" + "=" * 60)
    print(" 🛡️  CodeGuard Lite — Automated Code Reviewer & Security Scanner")
    print(" 🚀 Server running at: http://127.0.0.1:5000")
    print(" 🔒 Zero-Execution Static AST Security Engine Active")
    print("=" * 60 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
