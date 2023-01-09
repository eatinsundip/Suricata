# ET Open Submission
### January 9th, 2023
### DCRat Activity Detected


## Resources

1. https://tria.ge/230107-eynj2acf87/behavioral2
2. https://tria.ge/230107-fa3jqagb8t/behavioral3
3. https://app.any.run/tasks/f314829e-d378-445d-8749-43a465121737/


If I don't have anything here just let me know.

This [triage](https://tria.ge/230107-fa3jqagb8t/behavioral3) run for DCRat fired an older rule of **2034194**

```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE DCRAT Activity (GET)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:".php?"; content: "&"; pcre: "/^(?:[a-f0-9]{2}){16}=(?:[a-f0-9]{2}){16}&(?:[a-f0-9]{2}){16}=(?=[a-z0-9A-Z]{0,32}[A-Z][a-z][A-Z][a-z][A-Z])/R"; http.header_names; content:"|0d 0a|Accept|0d 0a|Content-Type|0d 0a|User-Agent|0d 0a|Host|0d 0a|Connection|0d 0a 0d 0a|"; bsize:56; fast_pattern; reference:url,twitter.com/James_inthe_box/status/1448751827046985746; reference:md5,60cf8c1093d596a44dc997d00caae463; classtype:trojan-activity; sid:2034194; rev:2; metadata:attack_target Client_Endpoint, created_at 2021_10_15, deployment Perimeter, former_category MALWARE, signature_severity Major, updated_at 2021_10_15;)```

This newer [triage](https://tria.ge/230107-eynj2acf87/behavioral2) instance I found and re-ran did not trip anything but some informational alerts.

This is why I wrote a new signature to detect on the client>server pattern I keep seeing.

```
/bot5861146625:AAEHo1wi939JhVuLzstg9mWqpsc_ntWfbTQ/sendPhoto?chat_id=5058531872&caption=%E2%9D%95%20User%20connected%20%E2%9D%95%0A%E2%80%A2%20ID%3A%20a683d399ec4da81b2f69cbd3e01b93a58b431a4e%0A%E2%80%A2%20Comment%3A%2025.12-26.12%0A%0A%E2%80%A2%20User%20Name%3A%20Admin%0A%E2%80%A2%20PC%20Name%3A%20TMKNGOMU%0A%E2%80%A2%20OS%20Info%3A%20Windows%2010%20Pro%0A%0A%E2%80%A2%20IP%3A%20154.61.71.13%0A%E2%80%A2%20GEO%3A%20NL%20%2F%20Aalsmeerderbrug%0A%0A%E2%80%A2%20Working%20Directory%3A%20C%3A%5CUsers%5CAll%20Users%5CDesktop%5Cservices.exe
```

Once decoded an human readable, they always seem to come out very similar.


```
/bot5861146625:AAEHo1wi939JhVuLzstg9mWqpsc_ntWfbTQ/sendPhoto?chat_idP58531872&caption=❕ User connected ❕
• ID: a683d399ec4da81b2f69cbd3e01b93a58b431a4e
• Comment: 25.12-26.12

• User Name: Admin
• PC Name: TMKNGOMU
• OS Info: Windows 10 Pro

• IP: 154.61.71.13
• GEO: NL / Aalsmeerderbrug

• Working Directory: C:\Users\All Users\Desktop\services.exe
```

I generated a Flowsynth PCAP and built a signature based on it since the TLS was causing strange issues in the triage PCAP.

## Signature

```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE DCRAT Activity"; flow:established,to_server; http.uri; content:"/bot";startswith; content:"|2f|sendPhoto|3f|chat|5f|id|3d|"; distance:0; content:"caption|3d e2 9d 95 20|User|20|connected|20 e2 9d 95|"; distance:10; within:65; content:"|e2 80 a2 20|ID|3a 20|"; within:65; content:"|e2 80 a2 20|Comment|3a 20|"; distance:40; within:35; content:"|0a 0a e2 80 a2 20|User|20|Name|3a 20|"; distance:11; within:27; content:"|e2 80 a2 20|PC|20|Name|3a 20|"; distance:0; within:100; content:"|e2 80 a2 20|OS|20|Info|3a 20|"; within:100; content:"|e2 80 a2 20|IP|3a 20|"; within:100; content:"|20|GEO|3a 20|"; distance:7; within:20;  content:"|e2 80 a2 20|Working|20|Directory|3a 20|"; within:100; http.host; content:"api.telegram.org"; fast_pattern; reference:url,https://tria.ge/230107-eynj2acf87/behavioral2; classtype:trojan-activity; sid:1; rev:1;)```


[Flowsynth PCAP](flowsynth.pcap)

[Re-Ran Full PCAP](raran-full.pcapng)

[Old Run PCAP](old-run.pcapng)

[Dalton Instance](https://dalton.centraliowacybersec.com)
