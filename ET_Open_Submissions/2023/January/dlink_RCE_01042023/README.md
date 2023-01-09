# ET Open Submission
### January 4th, 2023
### Dlink RCE Detected


## Resources

1. https://github.com/CyberUnicornIoT/IoTvuln/blob/main/d-link/dir-846/D-Link%20dir-846%20SetIpMacBindSettings%20Command%20Injection%20Vulnerability.md
2. https://www.cisa.gov/uscert/ncas/bulletins/sb23-002

## Signature

```alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET Exploit Possible D-Link Unauthenticated RCE Detected)"; flow:to_server,established; http.method; content:"POST";  classtype:exploit-activity; sid:1; rev:1; metadata:attack_target Server, created_at 2022_01_04, deployment Perimeter, deployment Internal, former_category EXPLOIT, signature_severity Major, tag Exploit, updated_at 2023_01_04;)```
