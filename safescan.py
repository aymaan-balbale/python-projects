import requests
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import json
import threading
from urllib.parse import urljoin, urlparse
import re
from bs4 import BeautifulSoup

report = {"vulnerabilities": []}
malware_found = False  # Track if malware was found

severity_levels = {
    "Missing X-Content-Type-Options header": "Low",
    "Missing X-Frame-Options header": "Low",
    "Missing Strict-Transport-Security header": "Low",
    "SQL Injection vulnerability detected": "High",
    "XSS vulnerability detected": "Medium",
    "Suspicious pattern: eval": "Medium",
    "Suspicious pattern: document.write": "Medium",
    "Suspicious pattern: base64 string": "Medium",
    "Suspicious pattern: hex string": "Medium",
    "Suspicious pattern: iframe": "Medium",
    "Suspicious pattern: obfuscated script": "Medium",
    "Suspicious iframe source": "Medium",
    "Error fetching or parsing page": "Low"
}

def scan_headers(url):
    findings = []
    try:
        res = requests.get(url)
        headers = res.headers
        if 'X-Content-Type-Options' not in headers:
            findings.append("Missing X-Content-Type-Options header")
        if 'X-Frame-Options' not in headers:
            findings.append("Missing X-Frame-Options header")
        if 'Strict-Transport-Security' not in headers:
            findings.append("Missing Strict-Transport-Security header")
    except:
        findings.append("Error fetching or parsing page")
    return findings

def scan_sql_injection(url):
    findings = []
    payloads = [
        "' OR '1'='1", "' UNION SELECT NULL--", "1' AND 1=1 --", "1' OR 1=1 --", "' OR 1=1 #",
        "admin' --", "1'--", "admin' #"
    ]
    for p in payloads:
        test_url = url + ("?id=" + p)
        try:
            res = requests.get(test_url)
            if "sql" in res.text.lower() or "syntax" in res.text.lower() or "error" in res.text.lower():
                findings.append("SQL Injection vulnerability detected")
                break
        except:
            continue
    return findings

def scan_xss(url):
    findings = []
    payloads = [
        "<script>alert('x')</script>", "<img src=x onerror=alert('x')>", "<svg/onload=alert('x')>", 
        "<iframe src='javascript:alert(1)'></iframe>", "<script>document.write('XSS');</script>"
    ]
    for p in payloads:
        test_url = url + ("?search=" + p)
        try:
            res = requests.get(test_url)
            if p in res.text:
                findings.append("XSS vulnerability detected")
                break
        except:
            continue
    return findings

def malware_analysis(url):
    global malware_found  # Access the global variable
    findings = []
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.text, 'html.parser')
        scripts = soup.find_all("script")
        suspicious_patterns = ["eval", "document.write", "atob", "0x", "iframe"]
        for script in scripts:
            if script.string:
                for pattern in suspicious_patterns:
                    if pattern in script.string:
                        findings.append(f"Suspicious pattern: {pattern}")
                        malware_found = True  # Malware found
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "")
            if "http" in src and not urlparse(src).netloc.endswith(urlparse(url).netloc):
                findings.append("Suspicious iframe source")
                malware_found = True  # Malware found
    except:
        findings.append("Error fetching or parsing page")
    return findings

def crawl_links(url):
    links = []
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            full_url = urljoin(url, link['href'])
            if urlparse(full_url).netloc == urlparse(url).netloc:
                links.append(full_url)
    except:
        pass
    return links

def run_scan(url, do_malware):
    global malware_found  # Access the global variable
    malware_found = False  # Reset malware_found at the start of each scan
    all_findings = []
    
    # First, test the base URL
    for item in scan_headers(url):
        all_findings.append({"url": url, "issue": item})
    for item in scan_sql_injection(url):
        all_findings.append({"url": url, "issue": item})
    for item in scan_xss(url):
        all_findings.append({"url": url, "issue": item})
    if do_malware:
        for item in malware_analysis(url):
            all_findings.append({"url": url, "issue": item})

    # Now, crawl the website and test the discovered links
    discovered_links = crawl_links(url)
    for link in discovered_links:
        for item in scan_headers(link):
            all_findings.append({"url": link, "issue": item})
        for item in scan_sql_injection(link):
            all_findings.append({"url": link, "issue": item})
        for item in scan_xss(link):
            all_findings.append({"url": link, "issue": item})
        if do_malware:
            for item in malware_analysis(link):
                all_findings.append({"url": link, "issue": item})

    for item in all_findings:
        desc = vuln_descriptions.get(item["issue"], "No description available.")
        sev = severity_levels.get(item["issue"], "Low")
        item["description"] = desc
        item["severity"] = sev
        report["vulnerabilities"].append(item)

    return report

def perform_scan():
    url = url_entry.get()
    do_malware = malware_var.get()
    if not url:
        messagebox.showerror("Input Error", "Please enter a URL to scan.")
        return

    def log(msg, severity=None):
        if severity == "High":
            log_text.insert(tk.END, msg + "\n", "high")
        elif severity == "Medium":
            log_text.insert(tk.END, msg + "\n", "medium")
        elif severity == "Low":
            log_text.insert(tk.END, msg + "\n", "low")
        else:
            log_text.insert(tk.END, msg + "\n")
        log_text.see(tk.END)

    def thread_func():
        scan_result = run_scan(url, do_malware)
        for v in scan_result["vulnerabilities"]:
            log(f"[+] {v['issue']} at {v['url']} (Severity: {v['severity']})", v["severity"])

        # Summary
        severity_count = {"High": 0, "Medium": 0, "Low": 0}
        for v in scan_result["vulnerabilities"]:
            sev = v.get("severity", "Low")
            severity_count[sev] += 1

        log("\n--- Severity Summary ---")
        for level in ["High", "Medium", "Low"]:
            log(f"{level}: {severity_count[level]}", severity=level)

        # Add Malware Status
        log(f"\n--- Malware Found: {malware_found}", severity="High" if malware_found else "Low")
        
        status_label.config(text="Scan completed")

    threading.Thread(target=thread_func).start()
    status_label.config(text="Scanning...")

def save_report():
    if not report["vulnerabilities"]:
        messagebox.showinfo("Info", "No vulnerabilities to save.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
    if path:
        with open(path, "w") as f:
            json.dump(report, f, indent=4)
        messagebox.showinfo("Success", "Report saved successfully.")

vuln_descriptions = {
    "Missing X-Content-Type-Options header": "This header prevents MIME-type sniffing.",
    "Missing X-Frame-Options header": "Helps prevent clickjacking attacks.",
    "Missing Strict-Transport-Security header": "Forces secure connections to the server.",
    "SQL Injection vulnerability detected": "User input might be interfering with SQL queries.",
    "XSS vulnerability detected": "User input might be injected into HTML/JS code.",
    "Suspicious pattern: eval": "'eval' is commonly used in malicious JavaScript.",
    "Suspicious pattern: document.write": "Can lead to DOM-based XSS.",
    "Suspicious pattern: base64 string": "May be used to obfuscate malicious code.",
    "Suspicious pattern: hex string": "Possible obfuscated content.",
    "Suspicious pattern: iframe": "External iframes may be used for clickjacking or malware.",
    "Suspicious pattern: obfuscated script": "Code may be intentionally obscured.",
    "Suspicious iframe source": "Iframe from unknown source may contain harmful content.",
    "Error fetching or parsing page": "Could not connect or read page content."
}

# GUI Setup
app = tk.Tk()
app.title("Website Vulnerability Scanner")
app.geometry("800x600")

# Title Section
title_label = tk.Label(app, text="Website Vulnerability Scanner", font=("Helvetica", 16, "bold"))
title_label.pack(pady=10)

# URL Input Section
tk.Label(app, text="Enter Website URL:").pack(pady=5)
url_entry = tk.Entry(app, width=80)
url_entry.pack(pady=5)

# Malware Analysis Checkbox
malware_var = tk.BooleanVar()
tk.Checkbutton(app, text="Include Malware Analysis", variable=malware_var).pack(pady=5)

# Action Buttons
action_frame = tk.Frame(app)
action_frame.pack(pady=10)

tk.Button(action_frame, text="Start Scan", command=perform_scan).pack(side=tk.LEFT, padx=5)
tk.Button(action_frame, text="Save Report", command=save_report).pack(side=tk.LEFT, padx=5)

# Log Section
log_frame = tk.Frame(app)
log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

log_text = tk.Text(log_frame, wrap="word")
log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(log_frame, command=log_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
log_text.config(yscrollcommand=scrollbar.set)

# Color-Coding
log_text.tag_config("high", foreground="red")
log_text.tag_config("medium", foreground="orange")
log_text.tag_config("low", foreground="green")

# Status Label
status_label = tk.Label(app, text="Idle", relief=tk.SUNKEN, anchor=tk.W)
status_label.pack(fill=tk.X, side=tk.BOTTOM)

app.mainloop()
