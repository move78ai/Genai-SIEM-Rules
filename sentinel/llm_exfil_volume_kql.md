Microsoft Sentinel (KQL) Detection: High Volume Outbound AI Traffic

Author: Abhishek G Sharma, Move78 International, contact@move78int.com
Log Source Requirements: CommonSecurityLog (for third-party proxies/firewalls) or Defender for Endpoint Network events, provided they log outbound payload sizes.

The Query
This Kusto Query Language (KQL) script hunts for anomalous data uploads to LLM endpoints.kusto
// Define the Threat Intel feed of AI domains
let AIDomains = dynamic([
"chatgpt.com", "api.openai.com", "anthropic.com", "claude.ai",
"gemini.google.com", "perplexity.ai", "https://www.google.com/search?q=phind.com", "poe.com", "huggingface.co"
]);

// Set the Alert Threshold (e.g., 2,000,000 bytes / ~2MB)
let ByteThreshold = 2000000;

CommonSecurityLog

| where TimeGenerated > ago(24h)
// Filter for web/proxy traffic

| where DeviceFacility == "Proxy" or DeviceVendor in ("Palo Alto Networks", "Zscaler")
// Match against AI domains

| where DestinationHostName has_any (AIDomains) or RequestURL has_any (AIDomains)
// Aggregate Sent Bytes

| summarize TotalBytesSent = sum(SentBytes),
RequestCount = count(),
FirstSeen = min(TimeGenerated),
LastSeen = max(TimeGenerated)
by SourceUserName, SourceIP, DestinationHostName
// Apply DLP Threshold

| where TotalBytesSent > ByteThreshold
// Format output

| extend TotalMB = round(TotalBytesSent / 1048576.0, 2)
| project SourceUserName, SourceIP, DestinationHostName, TotalMB, RequestCount, FirstSeen, LastSeen
| sort by TotalMB desc