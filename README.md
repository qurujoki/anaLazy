# anaLazy

Get summary of existing scan reports for various IOCs from different providers.

|Command|IOC        |Providers|
|---    |---        |---
|ip     |IP address |AbuseIPDB, Shodan, VirusTotal
|domain |Domain     |VirusTotal
|url    |URL        |URLScan, VirusTotal
|hash   |Hash       |VirusTotal

## Requirements

- Python 3.10.
- API keys, either configured via [`anaLazy.cfg`](anaLazy.cfg), or environment variables `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY`.
  - https://developers.virustotal.com/reference/getting-started
  - https://docs.abuseipdb.com/#introduction

## Examples

### IP

```
anaLazy > ip 8.8.8.8
Full report            : https://www.abuseipdb.com/check/8.8.8.8
Last reported          : 2024-03-17T15:04:43+00:00
Abuse confidence score : 0/100
Domain                 : google.com
Hostnames              : dns.google
ISP                    : Google LLC
Country code           : US
Usage type             : Data Center/Web Hosting/Transit
Tor node               : False

Full report   : https://shodan.io/host/8.8.8.8
Last udpdated : 2024-03-17T09:49:24.807863
Tags          : 
ISP           : Google LLC
Ports         : 443, 53
Hostnames     : dns.google
Country       : United States
Domains       : dns.google
Organization  : Google LLC

Full report                 : https://virustotal.com/gui/ip-address/8.8.8.8
Last analysis               : 2024-03-17 02:08:38
Malicious score (vendors)   : 3/91
Malicious score (community) : 28/212
Tags                        : 
Country                     : US
AS owner                    : GOOGLE
SSL certificate CN          : dns.google
```

### Domain

```
anaLazy > url https://eg44.z5.web.core.windows.net/?bcda=%280101%29-87764-30682
Full report   : https://urlscan.io/result/4fbded92-c77f-40aa-9e0c-e8ca11841283/
Submission    : 2024-03-17T16:27:25.483Z
Score         : 100/100
Malicious     : True
Effective URL : https://eg44.z5.web.core.windows.net/windows/index.html?bcda=(0101)-87764-30682
Categories    : phishing
Brands        : techsupportscam
Tags          : phishing
Server        : Windows-Azure-Web/1.0 Microsoft-HTTPAPI/2.0
IP            : 20.60.153.228
ASN name      : MICROSOFT-CORP-MSN-AS-BLOCK, US

Full report                 : https://virustotal.com/gui/url/80e718b1c8d2f58efd7877ab4a6702c41ef64ed03a571dda9bbc873e0aa74dc0
Last analysis               : 2024-03-17 18:28:25
Malicious score (vendors)   : 1/93
Malicious score (community) : 0/0
Tags                        : trackers, external-resources, dom-modification
URL                         : https://eg44.z5.web.core.windows.net/?bcda=(0101)-87764-30682
Last final URL              : https://eg44.z5.web.core.windows.net/?bcda=(0101)-87764-30682
Title                       : コンピューターエラ
```
