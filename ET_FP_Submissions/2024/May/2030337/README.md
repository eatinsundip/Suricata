# ET Potential False Positive Submission
### May 24th, 2024
### sid:2030337

I tested the Apache Flink (CVE-2020-17519) last night in my lab and found there to be ample alerts. I did however find the `ET EXPLOIT VMware Spring Cloud Directory Traversal (CVE-2020-5410)` to be using the exact same technique. This fired the CVE-2020-5410 Sig for the CVE-2020-17519 exploit.

I don't know what ET procedure is for this but I thought I would just bring it up.

If another alert can be added, I believe the biggest difference is the Apache Flink exploit requires the path to start with `/jobmanager/logs/..%252f`

Something more like this?

```alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET EXPLOIT Apache Flink Directory Traversal (CVE-2020-17519)"; flow:established,to_server; http.method; content:"GET"; http.uri.raw; content:"/jobmanager/logs/"; startswith; content:"..%252f..%252f"; fast_pattern; reference:url,https://www.vicarius.io/vsociety/posts/cve-2020-17519-apache-flink-directory-traversal-vulnerability; reference:cve,2020-17519; classtype:attempted-admin; sid:1; rev:1; metadata:affected_product VMware, attack_target Server, created_at 2024_05_24, cve CVE_2020_17519, deployment Perimeter, former_category EXPLOIT, performance_impact Low, signature_severity Major, updated_at 2024_05_24;)```

## Resources

Replicated exploit in Docker with `docker run -d --name flink-jobmanager -p 8081:8081 flink:1.11.2 jobmanager`

[Job Link](https://dalton.securitymidwest.net/dalton/coverage/job/582843c84741da8c)

[Pcap Zip](https://github.com/eatinsundip/Suricata/files/15434992/apache.zip)

## Notes

Something else I noticed..

When browsing the flink site, the jobmanager url you get by browsing is `/jobmanager/logs`

![image](https://github.com/eatinsundip/Suricata/assets/43767555/548c1903-d553-420c-a31d-3f72a2a32c87)

The exploit however only works with `/job-manager/logs`

They aren't even using the same path.

![image](https://github.com/eatinsundip/Suricata/assets/43767555/8bd1f253-7138-4862-9a79-f06ec628521c)