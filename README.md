# MCPSentinel — MCP Server Security Scanner

Detects prompt injection and supply chain attacks in Model Context Protocol (MCP) servers using dual detection — keyword pattern matching AND ML-based semantic analysis.

## Dashboard Screenshots
![MCPSentinel Dashboard 1](sentinel%201.png)
![MCPSentinel Dashboard 2](sentinel%202.png)
![MCPSentinel Dashboard 3](sentinel%203.png)

## What it does
- Scans MCP server tool definitions for hidden malicious instructions
- Detects subtle prompt injections that bypass traditional keyword scanners
- Uses ML (TF-IDF + Logistic Regression) with 91.67% accuracy
- Generates risk scores (0-100) per tool and per server
- Live Flask dashboard with one-click scanning
## Multilingual Detection (New)
Detects prompt injections in 50+ languages using 
paraphrase-multilingual-MiniLM-L12-v2:

| Language | Test Result | Confidence |
|---|---|---|
| Chinese | MALICIOUS ✅ | 68% |
| Arabic | MALICIOUS ✅ | 70% |
| Russian | MALICIOUS ✅ | 93% |
| French | MALICIOUS ✅ | 92% |
| Spanish | MALICIOUS ✅ | 97% |
| Japanese | MALICIOUS ✅ | 85% |

## Why it matters
MCP (Model Context Protocol) is the fastest-growing AI integration standard in 2026. Tool poisoning attacks embed hidden instructions in MCP tool descriptions that AI agents blindly follow. No open-source scanner existed for this attack surface before MCPSentinel.

## Tech Stack
Python · scikit-learn · TF-IDF · Logistic Regression · Flask · JSON

## Detection Methods
1. Keyword pattern matching — catches obvious injections
2. ML semantic analysis — catches subtle disguised attacks
3. URL detection — flags suspicious external endpoints
4. Permission analysis — flags dangerous privilege claims

## Results
| MCP Server | Risk Level | Score |
|---|---|---|
| file-reader (safe) | LOW | 0/100 |
| document-processor (subtle attack) | HIGH | 57/100 |
| file-reader-backdoor (obvious attack) | CRITICAL | 100/100 |

## Setup
1. Clone repo
2. pip3 install scikit-learn flask pandas numpy
3. python3 scanner/ml_detector.py
4. python3 dashboard/app.py
5. Open http://localhost:5001
