# GenAI SIEM Rules 🕵️‍♂️📊

A SIEM Detection Engineering rule pack to detect proprietary data exfiltration to unauthorized SaaS LLMs via outbound payload volume analysis.

![A_dark_portraitoriented_2k_202602222205](https://github.com/user-attachments/assets/7b05c0aa-361e-4bf4-9911-823ce90b5d2f)

## 🚨 The Problem: Why DNS Blocking Fails for GenAI

Most enterprises attempt to manage "Shadow AI" by blocking domains like `chatgpt.com` at the DNS level. This fails for three critical reasons:

1. Bypass: Developers easily bypass local DNS sinkholes using DNS-over-HTTPS (DoH) or personal VPNs.
2. API Wrappers: Data is often exfiltrated via backend APIs or obscure Vercel/HuggingFace wrappers, not the main front end domains.
3. The Authorized Use Trap: If your organization *allows* AI tools for general productivity, DNS logs cannot differentiate between a harmless query (500 bytes) and a developer pasting 10,000 lines of proprietary source code (50,000+ bytes).

## ⚡ The Solution: Volumetric Payload Analysis

You cannot exfiltrate 5 Megabytes of source code in a 50 byte packet.

To detect true Data Loss Prevention (DLP) events related to GenAI, Security Operations Centers (SOCs) must pivot from DNS logs to Proxy/Next Gen Firewall (NGFW) logs. 

This repository contains SIEM queries designed to aggregate `bytes_out` (outbound traffic volume) to known AI infrastructure. It isolates users and endpoints uploading anomalously large payloads, separating legitimate chat queries from massive data uploads.

## 🛠️ Repository Contents

* `/threat_intel`: A continually updated CSV of known AI SaaS and API domains (`ai_domains_list.csv`).
* `/splunk`: SPL queries for Splunk Enterprise/Cloud.
* `/sentinel`: KQL queries for Microsoft Sentinel.
* `/elastic`: Lucene/ES|QL queries for Elastic Security.

## 🚀 Quick Start

1. Download the `ai_domains_list.csv` from the `/threat_intel` directory and import it as a lookup table in your SIEM.
2. Navigate to your respective SIEM folder (e.g., `/sentinel`).
3. Copy the detection logic and adjust the `ByteThreshold` (default is set to ~2MB) to match your enterprise baseline.
4. Deploy as a scheduled hunt or an active alert rule.

## ⚠️ Legal & Compliance Notice

These queries analyze network metadata and data transfer volumes. Before deploying these rules in a production environment, ensure your organization has the legal authority to monitor employee outbound traffic volumes. You must adhere to local privacy, telecommunications, and labor laws (e.g., GDPR in the EU, PIPL in China). This tool is for authorized threat hunting and DLP monitoring only.

## 🔗 About Move78 International

We build governance frameworks for the Agentic AI era. Finding Shadow AI is step one. Governing it without killing developer velocity is step two.

Need help building an Enterprise AI Gateway or an enforceable Acceptable Use Policy?

Contact us for an AgentClaw Controls Toolkit (ACT) assessment at contact@move78int.com.
