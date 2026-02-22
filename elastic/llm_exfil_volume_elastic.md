Elastic Security / Kibana Detection: High Volume Outbound AI Traffic

Author: Abhishek G Sharma, Move78 International, contact@move78int.com
Log Source Requirements: Network packet capture logs, Zeek, or Proxy logs ingested via Filebeat/Elastic Agent containing network.bytes_written or source.bytes.

The Query (ES|QL)
Elastic recently introduced ES|QL, which is vastly superior to Lucene for aggregations like byte counting.esql
// Search across network indices
FROM logs-network*, logs-ti_ti_proxy*
// Filter for AI domains (use wildcard matching)

| WHERE destination.domain LIKE "chatgpt.com"
OR destination.domain LIKE "api.openai.com"
OR destination.domain LIKE "anthropic.com"
OR destination.domain LIKE "claude.ai"
OR destination.domain LIKE "gemini.google.com"
OR destination.domain LIKE "huggingface.co"
// Aggregate the outbound bytes

| STATS TotalBytesOut = SUM(network.bytes_written),
InteractionCount = COUNT(network.bytes_written)
BY source.user.name, source.ip, destination.domain
// Alert Threshold: Greater than 2,000,000 Bytes (2MB)

| WHERE TotalBytesOut > 2000000
// Calculate Megabytes

| EVAL Total_MB = TotalBytesOut / 1048576
| KEEP source.user.name, source.ip, destination.domain, Total_MB, InteractionCount
| SORT Total_MB DESC
| LIMIT 50