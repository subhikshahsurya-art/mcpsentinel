# MCPSentinel — MCP Server Security Scanner

Detects prompt injection and supply chain attacks in Model Context Protocol (MCP) servers using dual detection — keyword pattern matching AND ML-based semantic analysis.

## Dashboard Screenshot
![MCPSentinel Dashboard](dashboard.png)

## What it does
- Scans MCP server tool definitions for hidden malicious instructions
- Detects subtle prompt injections that bypass traditional keyword scanners
- Uses ML (TF-IDF + Logistic Regression) with 91.67% accuracy
- Generates risk scores (0-100) per tool and per server
- Live Flask dashboard with one-click scanning

## Why it matters
MCP (Model Context Protocol) is the fastest-growing AI integration standard in 2026. Tool poisoning attacks embed hidden instructions in MCP tool
