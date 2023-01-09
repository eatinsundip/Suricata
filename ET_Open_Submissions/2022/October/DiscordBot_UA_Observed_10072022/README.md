# ET Open Submission
### October 7th, 2022
### DiscordBot UA Observed


## Resources

1. https://tria.ge/221006-p5rv5shfek/behavioral2


## Signature

```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Discord Bot User-Agent Observed "; flow:established,to_server; http.user_agent; content:"DiscordBot"; startswith; reference:url,https://github.com/RogueException/Discord.Net; classtype:misc-activity; sid:1; rev:1;)```


[028e7d8956df352 PCAP](028e7d8956df352.pcap)

[Dump PCAP](dump.pcapng)

[Dalton Instance](https://dalton.centraliowacybersec.com)
