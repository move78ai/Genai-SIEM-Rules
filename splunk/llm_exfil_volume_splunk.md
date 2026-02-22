Splunk Detection: High Volume Outbound AI Traffic

Author: Abhishek G Sharma, Move78 International, contact@move78int.com
Log Source Requirements: Proxy Logs (Zscaler, BlueCoat, Squid) or NGFW Traffic Logs (Palo Alto, Fortinet) that record bytes_out or sent_byte.

The Query
This SPL query calculates the total outbound bytes sent by each user/IP to known AI domains over a 24-hour period. It filters out low-volume "chat" traffic and alerts on high-volume "paste/upload" traffic.spl
// Define the AI Domains (Alternatively, use the ai_domains_list.csv lookup table)

| eval ai_domains="chatgpt.com,api.openai.com,anthropic.com,claude.ai,gemini.google.com,perplexity.ai,https://www.google.com/search?q=phind.com,poe.com,huggingface.co"

// Assuming index=proxy or index=firewall
index=network (sourcetype="pan:traffic" OR sourcetype="zscaler:lss")

| where match(dest_domain, replace(ai_domains, ",", "|"))

// Aggregate outbound bytes by user and destination

| stats sum(bytes_out) as TotalBytesSent, count as RequestCount by src_user, src_ip, dest_domain

// Convert to Megabytes for readability

| eval Total_MB_Sent = round(TotalBytesSent / 1024 / 1024, 2)

// ALERT THRESHOLD: Filter for users sending more than 2 Megabytes
// Adjust this threshold based on your enterprise baseline

| where Total_MB_Sent > 2.0

| sort - Total_MB_Sent
| rename src_user as "User", src_ip as "Source IP", dest_domain as "AI Service", Total_MB_Sent as "Total Data Exfiltrated (MB)"