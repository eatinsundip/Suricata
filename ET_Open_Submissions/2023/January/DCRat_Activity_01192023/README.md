# ET Open Submission
### January 19th, 2023
### DCRat Activity Detected


## Resources

1. https://tria.ge/230107-eynj2acf87/behavioral2

This is an addition to a sginature I submitted last week. These are signatures are for the response from the telegram API that might be seen getting sent back to the client.

The encoded http response below.

```
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sat, 07 Jan 2023 04:22:09 GMT
Content-Type: application/json
Content-Length: 1358
Connection: keep-alive
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Expose-Headers: Content-Length,Content-Type,Date,Server,Connection

{"ok":true,"result":{"message_id":210,"from":{"id":5861146625,"is_bot":true,"first_name":"DCRAT BOT","username":"dcra9bot"},"chat":{"id":5058531872,"first_name":"Meei [15503/100000]","username":"Meei_Zuko","type":"private"},"date":1673065329,"photo":[{"file_id":"AgACAgIAAxkDAAPSY7jzcRhttP7T4Xnauf47FJiUeXUAArfAMRuQcclJQnpgvH5M14QBAAMCAANzAAMtBA","file_unique_id":"AQADt8AxG5BxyUl4","file_size":1241,"width":90,"height":51},{"file_id":"AgACAgIAAxkDAAPSY7jzcRhttP7T4Xnauf47FJiUeXUAArfAMRuQcclJQnpgvH5M14QBAAMCAANtAAMtBA","file_unique_id":"AQADt8AxG5BxyUly","file_size":13699,"width":320,"height":180},{"file_id":"AgACAgIAAxkDAAPSY7jzcRhttP7T4Xnauf47FJiUeXUAArfAMRuQcclJQnpgvH5M14QBAAMCAAN4AAMtBA","file_unique_id":"AQADt8AxG5BxyUl9","file_size":47772,"width":800,"height":450},{"file_id":"AgACAgIAAxkDAAPSY7jzcRhttP7T4Xnauf47FJiUeXUAArfAMRuQcclJQnpgvH5M14QBAAMCAAN5AAMtBA","file_unique_id":"AQADt8AxG5BxyUl-","file_size":92603,"width":1280,"height":720}],"caption":"\u2755 User connected \u2755\n\u2022 ID: a683d399ec4da81b2f69cbd3e01b93a58b431a4e\n\u2022 Comment: 25.12-26.12\n\n\u2022 User Name: Admin\n\u2022 PC Name: TMKNGOMU\n\u2022 OS Info: Windows 10 Pro\n\n\u2022 IP: 154.61.71.13\n\u2022 GEO: NL / Aalsmeerderbrug\n\n\u2022 Working Directory: C:\\Users\\All Users\\Desktop\\services.exe","caption_entities":[{"offset":162,"length":12,"type":"url"}]}}
```


I generated a Flowsynth PCAP and built a few signatures from the PCAP.

## Signature

```alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN DCRAT Response Body 1)"; flow:established,from_server; http.stat_code; content:"200"; bsize:3; http.response_body; content:"|7b 22|ok|22 3a|true|2c 22|result|22 3a 7b 22|"; fast_pattern; startswith; content:"|22|is|5f|bot|22 3a|true|2c 22|first|5f|name|22 3a 22|DCRAT|20|BOT|22 2c 22|username|22 3a 22|dcra9bot|22|";  distance:40; within:60; reference:url,https://tria.ge/230107-eynj2acf87/behavioral2; classtype:trojan-activity; sid:1; rev:1;)```

```alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN DCRAT Response Body 2)"; flow:established,from_server; http.stat_code; content:"200"; bsize:3; http.response_body; content:"User|20|connected"; fast_pattern; content:"|20|ID|3a 20|"; distance:14; within:6; content:"|20|Comment|3a 20|"; distance:40; within:20; content:"|20|User|20|Name|3a 20|"; distance:15; within:20; content:"|20|PC|20|Name|3a 20|"; within:100; content:"|20|OS|20|Info|3a 20|"; within:100; content:"|20|IP|3a 20|"; within:100; content:"|20|GEO|3a 20|"; distance:15; within:12; content:"|20|Working|20|Directory|3a 20|"; within:100; reference:url,https://tria.ge/230107-eynj2acf87/behavioral2; classtype:trojan-activity; sid:2; rev:1;)```

[Dalton Job ID](https://dalton.centraliowacybersec.com/dalton/coverage/job/de95e792b5056255)

## Downloads

[Flowsynth PCAP](flowsynth.pcap)
