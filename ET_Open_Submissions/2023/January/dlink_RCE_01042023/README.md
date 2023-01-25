# ET Open Submission
### January 4th, 2023
### Dlink RCE Detected


## Resources

1. https://github.com/CyberUnicornIoT/IoTvuln/blob/main/d-link/dir-846/D-Link%20dir-846%20SetIpMacBindSettings%20Command%20Injection%20Vulnerability.md
2. https://www.cisa.gov/uscert/ncas/bulletins/sb23-002

## Signature

```alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET Exploit Possible D-Link Unauthenticated RCE Detected)"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/HNAP1/"; startswith; http.content_type; content:"application/json"; http.request_body; content:"|7b 22|SetIpMacBindSettings|22 3a 7b 22|lan|5f|unit|22 3a 22|0|22 2c 22|lan|28|0|29 5f|dhcps|5f|staticlist|22 3a 22|1|2c|"; startswith; pcre:"/`.{1,100}`.{1,10},[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2},[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}"}}\z/"; classtype:exploit-activity; sid:1; rev:1; metadata:attack_target Server, created_at 2022_01_04, deployment Perimeter, deployment Internal, former_category EXPLOIT, signature_severity Major, tag Exploit, updated_at 2023_01_04;)```
