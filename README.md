# anaLazy

Get summary and link for existing scan results for artifacts from various providers:

|Command|Artifact   |Provider(s)|
|---    |---        |---
|ip     |IP address |AbuseIPDB, Shodan, VirusTotal
|domain |Domain     |VirusTotal
|url    |URL        |URLScan, VirusTotal
|hash   |Hash       |VirusTotal

## Requirements

- Python3 (no other dependencies are required as only builtin modules are used)
- API keys are read from environment variables, and following providers require the key:
    - [VIRUSTOTAL](https://developers.virustotal.com/reference/getting-started)
    - [ABUSEIPDB](https://docs.abuseipdb.com/#introduction)


## Example

```
anaLazy > ip 8.8.4.4

https://shodan.io/host/8.8.4.4

  ISP          : Google LLC
  Ports        : 443, 53
  Hostnames    : dns.google
  Country      : United States
  Domains      : dns.google
  Organization : Google LLC

https://www.abuseipdb.com/check/8.8.4.4

  Abuse confidence score : 0/100
  Domain                 : google.com
  Hostnames              : dns.google
  ISP                    : Google LLC
  Country code           : US
  Usage type             : Data Center/Web Hosting/Transit
  Tor node               : False

https://virustotal.com/gui/ip-address/8.8.4.4

  Malicious score (vendors)   : 1/87
  Malicious score (community) : 3/25
  Country                     : US
  AS owner                    : GOOGLE
  SSL certificate CN          : dns.google
```
