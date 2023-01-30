# ET Open Submission
### January 30th, 2023
### GCleaner Malware Activity


## Resources

I think I have something interesting here but feedback would defeinitely help on this one. I am not completely sure.

The sandbox was making GET connections to known malicious IPs from VirusTotal.

The VT links for the IPs I am seeing.

1. https://tria.ge/230130-trm29acf8w
2. [45.12.253.56](https://www.virustotal.com/gui/ip-address/45.12.253.56/relations)
3. [45.12.253.72](https://www.virustotal.com/gui/ip-address/45.12.253.72/relations)
4. [45.12.253.75](https://www.virustotal.com/gui/ip-address/45.12.253.75/relations)

## Signatures

### Signature #1

The first sig is to detect the beaconing going to **45.12.253.72**

The requests all looked the same across all the tests I ran.

```
GET /default/stuk.php HTTP/1.1
Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1
Accept-Language: ru-RU,ru;q=0.9,en;q=0.8
Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1
Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0
User-Agent: OK
Host: 45.12.253.72
Connection: Keep-Alive
Cache-Control: no-cache
```

```alert http $HOME_NET any -> $EXTERNAL_NET any msg:"ET TROJAN GCleaner Beacon"; flow:established,from_client; http.request_line; content:"GET|20 2f|default|2f|stuk|2e|php|20|HTTP|2f|1|2e|1"; bsize:30; http.header_names; content:"|0d 0a|Accept|0d 0a|Accept|2d|Language|0d 0a|Accept|2d|Charset|0d 0a|Accept|2d|Encoding|0d 0a|User|2d|Agent|0d 0a|Host|0d 0a|Connection|0d 0a|Cache|2d|Control|0d 0a 0d 0a|"; http.user_agent; content:"OK"; bsize:2; fast_pattern; reference:url,https://tria.ge/230130-trm29acf8w; classtype:trojan-activity; sid:1; rev:1;)```



### Signature #2

The 2nd sig is based on this header info that seemed to request a download.

```
GET /default/puk.php HTTP/1.1
Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1
Accept-Language: ru-RU,ru;q=0.9,en;q=0.8
Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1
Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0
User-Agent: OK
Host: 45.12.253.72
Connection: Keep-Alive
Cache-Control: no-cache
```

```alert http $HOME_NET any -> $EXTERNAL_NET any msg:"ET TROJAN GCleaner (File Download Request)"; flow:established,from_client; http.request_line; content:"GET|20 2f|default|2f|puk|2e|php|20|HTTP|2f|1|2e|1"; bsize:29; http.header_names; content:"|0d 0a|Accept|0d 0a|Accept|2d|Language|0d 0a|Accept|2d|Charset|0d 0a|Accept|2d|Encoding|0d 0a|User|2d|Agent|0d 0a|Host|0d 0a|Connection|0d 0a|Cache|2d|Control|0d 0a 0d 0a|"; http.user_agent; content:"OK"; bsize:2; fast_pattern; reference:url,https://tria.ge/230130-trm29acf8w; classtype:trojan-activity; sid:2; rev:1;)```



### Signature #3

The 3rd sig is looking for the **puk.php** response that serves a download.

```alert http $EXTERNAL_NET any -> $HOME_NET any msg:"ET TROJAN GCleaner (Potential Malicious File Download)"; flow:established,from_server; http.response_line; content:"HTTP|2f|1|2e|1|20|200|20|OK"; bsize:15; http.header_names; content:"|0d 0a|Cache-Control|0d 0a|Content|2d|Disposition|0d 0a|Content-Transfer-Encoding|0d 0a|Content-Length|0d 0a|Keep-Alive|0d 0a|Connection|0d 0a|Content-Type|0d 0a 0d 0a|";  reference:url,https://tria.ge/230130-trm29acf8w; classtype:trojan-activity; sid:3; rev:1;)```



### Signature #4

The 4th sig is looking for **/dll.php** and the user-agent of **B** in the client GET request.

```alert http $HOME_NET any -> $EXTERNAL_NET any msg:"ET TROJAN GCleaner (Beacon 2)"; flow:established,from_client; http.request_line; content:"GET|20 2f|dll|2e|php|20|HTTP|2f|1|2e|1"; http.header_names; content:"Accept|0d 0a|Accept-Language|0d 0a|Accept-Charset|0d 0a|Accept-Encoding|0d 0a|User-Agent|0d 0a|Host|0d 0a|Connection|0d 0a|Cache-Control|0d 0a|"; http.user_agent; content:"B"; bsize:1; reference:url,https://tria.ge/230130-trm29acf8w; classtype:trojan-activity; sid:4; rev:1;)```



### Signature #5

The 5th sig is looking for **/advertisting/plus.php** and the user-agent of **OK** in the client GET request.

This one might not be as needed as the others. I never found anything related to the PHP variables put in it but it did stand out and was interesting.

```alert http $HOME_NET any -> $EXTERNAL_NET any msg:"ET TROJAN GCleaner (Beacon 3)"; flow:established,from_client; http.request_line; content:"GET|20 2f|advertisting|2f|plus|2e|php|3f|s|3d|NOSUB|26|str|3d|mixtwo|26|substr|3d|mixinte|20|HTTP|2f|1|2e|1"; bsize:69; http.header_names; content:"|0d 0a|Accept|0d 0a|Accept|2d|Language|0d 0a|Accept|2d|Charset|0d 0a|Accept|2d|Encoding|0d 0a|User|2d|Agent|0d 0a|Host|0d 0a|Connection|0d 0a|Cache|2d|Control|0d 0a 0d 0a|"; http.user_agent; content:"OK"; bsize:2; fast_pattern;  reference:url,https://tria.ge/230130-trm29acf8w; classtype:trojan-activity; sid:5; rev:1;)```

## All Sigs Together

```
alert http $HOME_NET any -> $EXTERNAL_NET any msg:"ET TROJAN GCleaner (Beacon 1)"; flow:established,from_client; http.request_line; content:"GET|20 2f|default|2f|stuk|2e|php|20|HTTP|2f|1|2e|1"; bsize:30; http.header_names; content:"|0d 0a|Accept|0d 0a|Accept|2d|Language|0d 0a|Accept|2d|Charset|0d 0a|Accept|2d|Encoding|0d 0a|User|2d|Agent|0d 0a|Host|0d 0a|Connection|0d 0a|Cache|2d|Control|0d 0a 0d 0a|"; http.user_agent; content:"OK"; bsize:2; fast_pattern; reference:url,https://tria.ge/230130-trm29acf8w; classtype:trojan-activity; sid:1; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any msg:"ET TROJAN GCleaner (File Download Request)"; flow:established,from_client; http.request_line; content:"GET|20 2f|default|2f|puk|2e|php|20|HTTP|2f|1|2e|1"; bsize:29; http.header_names; content:"|0d 0a|Accept|0d 0a|Accept|2d|Language|0d 0a|Accept|2d|Charset|0d 0a|Accept|2d|Encoding|0d 0a|User|2d|Agent|0d 0a|Host|0d 0a|Connection|0d 0a|Cache|2d|Control|0d 0a 0d 0a|"; http.user_agent; content:"OK"; bsize:2; fast_pattern; reference:url,https://tria.ge/230130-trm29acf8w; classtype:trojan-activity; sid:2; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any msg:"ET TROJAN GCleaner (Potential Malicious File Download)"; flow:established,from_server; http.response_line; content:"HTTP|2f|1|2e|1|20|200|20|OK"; bsize:15; http.header_names; content:"|0d 0a|Cache-Control|0d 0a|Content|2d|Disposition|0d 0a|Content-Transfer-Encoding|0d 0a|Content-Length|0d 0a|Keep-Alive|0d 0a|Connection|0d 0a|Content-Type|0d 0a 0d 0a|";  reference:url,https://tria.ge/230130-trm29acf8w; classtype:trojan-activity; sid:3; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any msg:"ET TROJAN GCleaner (Beacon 2)"; flow:established,from_client; http.request_line; content:"GET|20 2f|dll|2e|php|20|HTTP|2f|1|2e|1"; http.header_names; content:"Accept|0d 0a|Accept-Language|0d 0a|Accept-Charset|0d 0a|Accept-Encoding|0d 0a|User-Agent|0d 0a|Host|0d 0a|Connection|0d 0a|Cache-Control|0d 0a|"; http.user_agent; content:"B"; bsize:1; reference:url,https://tria.ge/230130-trm29acf8w; classtype:trojan-activity; sid:4; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any msg:"ET TROJAN GCleaner (Beacon 3)"; flow:established,from_client; http.request_line; content:"GET|20 2f|advertisting|2f|plus|2e|php|3f|s|3d|NOSUB|26|str|3d|mixtwo|26|substr|3d|mixinte|20|HTTP|2f|1|2e|1"; bsize:69; http.header_names; content:"|0d 0a|Accept|0d 0a|Accept|2d|Language|0d 0a|Accept|2d|Charset|0d 0a|Accept|2d|Encoding|0d 0a|User|2d|Agent|0d 0a|Host|0d 0a|Connection|0d 0a|Cache|2d|Control|0d 0a 0d 0a|"; http.user_agent; content:"OK"; bsize:2; fast_pattern;  reference:url,https://tria.ge/230130-trm29acf8w; classtype:trojan-activity; sid:5; rev:1;)
```

## Question

I am not entirely sure what the quote on quote **Beacons** are. A few look like beacons since they were consistant but the 5th sig does not. I just wan't sure what to call it. It's definitely abnormal to me.

[Dalton Job ID](https://dalton.centraliowacybersec.com/dalton/coverage/job/7e0c34877ec12896)

## Downloads

[GCleaner PCAP](gcleaner_malware.pcapng)
