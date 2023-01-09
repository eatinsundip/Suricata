# ET Open Submission
### December 13th, 2022
### UPX Miner (phonk) Detected


## Resources

1. https://tria.ge/221206-2fvxqadb5v/behavioral1
2. https://tria.ge/221209-ygxwxsea85/behavioral1

## Signatures

### Alerts on the /BEBRA.php uri with the machine data exfil. Need help on skipping the data foir the screenshot since it's long. I want the rest of the meat at the end.

```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET Phonk Trojan Detected"; flow:established,to_server; http.uri; pcre:"/\/[A-Z]{4,6}.php/"; http.method; content:"POST"; http.header_names; content:"|0d 0a|Content-Type|0d 0a|Host|0d 0a|Content-Length|0d 0a|Expect|0d 0a|Connection|0d 0a 0d 0a|"; http.content_type; content:"application/x-www-form-urlencoded"; http.request_body; content:"filez="; reference:url,https://tria.ge/221206-2fvxqadb5v/behavioral1; classtype:trojan-activity; sid:1; rev:1;)```


### Alerts on the .phonk file extension in the response as suspicious (generic)

```alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO suspicious file extension (.phonk)"; flow:established,to_client; fileext:"phonk"; reference:url,https://tria.ge/221206-2fvxqadb5v/behavioral1; classtype:misc-activity; sid:1; rev:1;)```


### Alerts on the client side posts with the ID

```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET Phonk Trojan Detected"; flow:established,to_server; http.uri; pcre:"/\/[A-Z]{7,9}.php/"; http.method; content:"POST"; http.header_names; content:"|0d 0a|Content-Type|0d 0a|Host|0d 0a|Content-Length|0d 0a|Expect"; http.content_type; content:"application/x-www-form-urlencoded"; http.request_body;pcre:"/id=[0-9]{10}/"; reference:md5,https://tria.ge/221206-2fvxqadb5v/behavioral1; classtype:trojan-activity; sid:1; rev:1;)```


##Notes

1. The http.request_body of "id=5125131275" is always the same but I think a 10 digit pcre might be safer?
How to trip on no UA?
2. I haven't dug into what the .phonk file is yet.


[Flowsynth PCAP](flowsynth.pcap)

[Dalton Instance](https://dalton.centraliowacybersec.com)
