# ET Open Submission
### October 6th, 2022
### SmokeLoader C2 Activity Detected


## Resources

1. https://tria.ge/221005-yxxwvsffhk/behavioral1
2. https://tria.ge/221005-yx1mrafdh6/behavioral1
3. https://tria.ge/221005-yymghsfdh9/behavioral1
4. https://tria.ge/221005-yzjr1sfea5/behavioral1
5. https://tria.ge/221005-yznqzafea6/behavioral1
6. https://tria.ge/221005-y1ffzsfgak/behavioral1
7. https://tria.ge/221005-zdv4lafef2/behavioral1


## Signature

```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Smokeloader Post"; flow:established,to_server; http.method; content:"POST"; http.header_names; content:"|0d 0a|Connection|0d 0a|Content-Type|0d 0a|Accept|0d 0a|Referer|0d 0a|User-Agent|0d 0a|Content-Length|0d 0a|Host|0d 0a 0d 0a|"; bsize:81; http.referer; pcre:"/http|3a 2f 2f|[a-z]{5,10}.(com|org|net)/"; http.content_type; content:"application/x-www-form-urlencoded"; reference:md5,d58078226c4066f05926c70be7cf64a7; classtype:trojan-activity; sid:1; rev:1;)```


[Dump(1) PCAP](dump(1).pcapng)

[Dump(2) PCAP](dump(2).pcapng)

[Dump(3) PCAP](dump(3).pcapng)

[Dump(4) PCAP](dump(4).pcapng)

[Dump(5) PCAP](dump(5).pcapng)

[Dump(6) PCAP](dump(6).pcapng)

[Dump(7) PCAP](dump(7).pcapng)

[Dump(8) PCAP](dump(8).pcapng)

[Dalton Instance](https://dalton.centraliowacybersec.com)
