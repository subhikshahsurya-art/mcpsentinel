import json
import os
from datetime import datetime
from ml_detector import predict_injection
from multilingual_detector import analyze_multilingual

PATTERNS_FILE = "/home/subhikshah/MCPSentinel/knowledge/malicious_patterns.json"
RESULTS_FILE = "/home/subhikshah/MCPSentinel/scanner/scan_results.json"

def load_patterns():
    with open(PATTERNS_FILE) as f:
        return json.load(f)

def check_injection(text, patterns):
    text_lower = text.lower()
    found = []
    for pattern in patterns["injection_patterns"]:
        if pattern.lower() in text_lower:
            found.append(pattern)
    return found

def check_suspicious_urls(text, patterns):
    found = []
    for url in patterns["suspicious_urls"]:
        if url.lower() in text.lower():
            found.append(url)
    return found

def check_dangerous_permissions(text, patterns):
    text_lower = text.lower()
    found = []
    for perm in patterns["dangerous_permissions"]:
        if perm.lower() in text_lower:
            found.append(perm)
    return found

def calculate_risk(score):
    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"

def scan_tool(tool, patterns):
    findings = []
    name = tool.get("name", "unknown")
    description = tool.get("description", "")
    input_schema = json.dumps(tool.get("inputSchema", {}))
    full_text = description + " " + input_schema

    injections = check_injection(full_text, patterns)
    urls = check_suspicious_urls(full_text, patterns)
    permissions = check_dangerous_permissions(full_text, patterns)

    score = 0
    score += len(injections) * 30
    score += len(urls) * 20
    score += len(permissions) * 15

    if injections:
        findings.append({
            "type": "KEYWORD_INJECTION",
            "severity": "CRITICAL",
            "details": "Hidden instructions found: " + str(injections)
        })
    if urls:
        findings.append({
            "type": "SUSPICIOUS_URL",
            "severity": "HIGH",
            "details": "External URLs detected: " + str(urls)
        })
    if permissions:
        findings.append({
            "type": "DANGEROUS_PERMISSIONS",
            "severity": "HIGH",
            "details": "Dangerous permissions: " + str(permissions)
        })

    ml_result = predict_injection(full_text)
    if ml_result["confidence"] > 35:
        if ml_result["is_injection"]:
            ml_score = ml_result["confidence"]
            score = max(score, ml_score)
            findings.append({
                "type": "ML_INJECTION_DETECTED",
                "severity": "CRITICAL",
                "details": "ML detected injection with " + str(ml_result["confidence"]) + "% confidence"
            })
   # Multilingual detection
    multi_result = analyze_multilingual(full_text)
    if multi_result["is_injection"] and multi_result["confidence"] > 40:
        multi_score = multi_result["confidence"]
        score = max(score, multi_score)
        lang = multi_result["language_name"]
        findings.append({
            "type": "MULTILINGUAL_INJECTION",
            "severity": "CRITICAL",
            "details": lang + "-language injection detected with " +
                      str(multi_result["confidence"]) + "% confidence. " +
                      "Closest match: " + multi_result["closest_injection"]
        })

    score = min(score, 100)
    level = calculate_risk(score)

    return {
        "tool_name": name,
        "risk_score": round(score),
        "risk_level": level,
        "findings": findings
    }

def scan_mcp(filepath):
    print("Scanning:", filepath)
    with open(filepath) as f:
        mcp_config = json.load(f)
    patterns = load_patterns()
    server_name = mcp_config.get("name", "unknown")
    tools = mcp_config.get("tools", [])
    tool_results = []
    for tool in tools:
        result = scan_tool(tool, patterns)
        tool_results.append(result)
        print("Tool:", result["tool_name"], "| Risk:", result["risk_level"], "| Score:", result["risk_score"])
    max_score = max([r["risk_score"] for r in tool_results]) if tool_results else 0
    overall = calculate_risk(max_score)
    return {
        "server_name": server_name,
        "filepath": filepath,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "overall_risk": overall,
        "overall_score": max_score,
        "tools_scanned": len(tools),
        "tool_results": tool_results
    }

def run_scanner():
    sample_dir = "/home/subhikshah/MCPSentinel/sample_mcps"
    all_results = []
    for filename in os.listdir(sample_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(sample_dir, filename)
            result = scan_mcp(filepath)
            all_results.append(result)
            print("Overall risk for", result["server_name"], ":", result["overall_risk"])
            print("---")
    with open(RESULTS_FILE, "w") as f:
        json.dump(all_results, f, indent=2)
    print("Results saved to", RESULTS_FILE)

run_scanner()
