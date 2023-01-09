# ET Open Submission
### October 11th, 2022
### Teez DiscordBot Exfil Detected


## Resources

1. https://tria.ge/221006-p5rv5shfek/behavioral2



## Signature

```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Teez Discord Exfil"; flow:established,to_server; http.request_body; content:"|2a 2a|Browser|20|Cookies|2a 2a|"; content:"Content|2d|Disposition|3a 20|form|2d|data|3b 20|name|3d|"; distance:42; content:"|5f|Cookies|2e|txt|3b 20|filename|3d|"; within:300; content:"|5f|Cookies|2e|txt|3b 20|filename|2a 3d|utf|2d|8|27 27|"; within:300; content:"|5f|Cookies|2e|txt|0d 0a 0d 0a 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 0d 0a|Modified|20|Time|20 20 20 20 20 3a 20|"; within:100; reference:url,https://tria.ge/221006-p5rv5shfek/behavioral2; classtype:misc-activity; sid:1; rev:1;)```


[3ecb1228107e1ca PCAP](3ecb1228107e1ca.pcap)

[Dalton Instance](https://dalton.centraliowacybersec.com)
