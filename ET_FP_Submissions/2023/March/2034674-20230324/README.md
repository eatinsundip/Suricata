# ET Potential False Positive Submission
### March 24th, 2023
### GitLab Pre-Auth RCE (CVE-2021-22205)
### sid:2034674


I received a Filebeat IDS alert for an **Attempted Administrator Privilege Gain** with a possible Apache log4j RCE attempt.

I think this was all a massive coincidence once I looked at it.

## Full Message below

```
{

    timestamp: "2023-03-23T15:14:52.320621+0000",
    flow_id: 1114204629894871,
    in_iface: "bond0",
    event_type: "alert",
    src_ip: "178.249.209.175",
    src_port: 51820,
    dest_ip: "192.168.2.11",
    dest_port: 50240,
    proto: "UDP",
    community_id: "1:5JbeyuEf57gUzWcpQqjvYz3pspA=",
    alert: {
        action: "allowed",
        gid: 1,
        signature_id: 2034674,
        rev: 2,
        signature: "ET EXPLOIT Possible Apache log4j RCE Attempt - 2021/12/12 Obfuscation Observed M2 (udp) (CVE-2021-44228)",
        category: "Attempted Administrator Privilege Gain",
        severity: 1,
        metadata: {
            attack_target: [
                "Server"
            ],
            created_at: [
                "2021_12_12"
            ],
            cve: [
                "CVE_2021_44228"
            ],
            deployment: [
                "Internal",
                "Perimeter"
            ],
            former_category: [
                "EXPLOIT"
            ],
            signature_severity: [
                "Major"
            ],
            tag: [
                "Exploit"
            ],
            updated_at: [
                "2022_01_11"
            ]
        },
        rule: "alert udp any any -> [$HOME_NET,$HTTP_SERVERS] any (msg:\"ET EXPLOIT Possible Apache log4j RCE Attempt - 2021/12/12 Obfuscation Observed M2 (udp) (CVE-2021-44228)\"; content:\"|24 7b|\"; content:\"|24 7b 3a 3a|\"; within:100; fast_pattern; reference:cve,2021-44228; classtype:attempted-admin; sid:2034674; rev:2; metadata:attack_target Server, created_at 2021_12_12, cve CVE_2021_44228, deployment Perimeter, deployment Internal, former_category EXPLOIT, signature_severity Major, tag Exploit, updated_at 2022_01_11;)"
    },
    app_proto: "failed",
    payload_printable: "....!.]X..5.....w.7s...`g.Y...8......s=..\..:5/..$v.'..k..s..w...L..(........l../-...+..?..U.....`m.c....Y.:?.H\........1...)...~..9..H.JMA.....Z.m.ra._...?%.i....f....#.^op.D...${6E2/.N.P${::.&.d7...[.#k........FQ.c........h..AWd(.!.Q
    ...i[.......2...O..)I.l..L......Kt..^&..j#..Kw.Q..zl4.N\.p....+..v'.A=W..Z..c.;.s...D....]Z.b.J....]wM..o.z.O...............S]...l.....#....MP...<.....o......xZqw.....7}axn].\z.......*O.l..6..e..h........n.f...w.y.6........:=..^.H.....8r\7....!..J.L.......9...7YPN.....V..=...Z.? 9.M.Y^.[ ....u.....g...Rgb'4....*.....
    ..}.3...mP.n..o..D..:..T.j,.di...G.00.FGqe.U...IS..P.TO.E%........,m.....U\"O.......c&O...c..}......Dl........F.<..7.OVX...c...RP...j.b.[..&...b..-^.(.{Q..YC....,..4.p..|..Okp.....b,uQ..\"..(..]\
    z..T]7.....+.f.2.s?wy>...Y...yJ.F.....\"^.1kS%ig..{.4......
    .#...>C....i.PF.....+. ..r.~4#.lFm....8.../...m3.....PTt..k..(...H.Z./.t..H.sn......pS.....X
    ....1...'...R(.1..Y..<..t.....LN.0.{..z}..n.6..LF...4?....Z....u..........._..gds..

    .^..@.r.A...y2...r..........7(/........{o.{.@...cC.......5..$.(.xb...`.....8s*......./..W............4.`#.V.._81.\..U..3....<;...
    E.DCw!.2.;. 3.x..Y6....p..r...xf'.H^.yDX{6G.....<...L.|...AN..].c.PHz`...C/..5.....)..n.c ..=y2aH~o*..J$..A{......%.^....o...I.vs....|F6....y...4*...AB.]@.e.........A.0..G....GD.1....C..u]7.81
    -....KM...a!.Q.......B'...]oKA......M ..@......-....D .3&..N.[.h....9..H...R..JV..........$....(..+....z...~j..Oof\COdd..I1.j....OD.f..._sO&...",
    stream: 0,
    packet: "AkLAqAILaByiEv4+CABFAAXIzBgAAC8RcrCy+dGvwKgCC8psxEAFtBoHBAAAACHzXVi5wTUAAAAAAHeLN3PoBZhgZ81ZmAHjONCi2KKyEHM9Bxtc9rA6NS8Z/SR24yevymvIEHPjr3cWlPtM0wQoGujfzqutnO1sFu8vLdkaqiuVmj/N1FXrvPETEmBtmWPgic3sWe86P39IXN+v6Yr8DOfnMRXU7ing8sF+EfI5H/ZICUpNQbsS3aTZWgRtHnJh9V+PirY/Jbdpr97ghmbQsJIII+xeb3CLROuPzSR7NkUyL4lOtlAkezo68CaxZDcXmn9byyNr7oS7t9Oi5RZGUdJj5vGehO3jFwtorpJBV2QoLiG4UQoPvaRpWxG16oqzyokyBs/dT4OSKUmhbA/kTB/iHuYRt0t0Gv1eJuAAaiMAg0t3olHMjXpsNJdOXM5wossEiCvQq3Yn+UE9V+a6WgfEY9U7gnO6u6hEnYkZ0F1almKsSrUe689dd02MD2/nestPjPuXqLPDygPKl/8JGY7LU12MnhNs9J2i5ZQj3cyTFE1Q3cWyPBi+AomRb6ys0Bbzy3hacXewo/jx4jd9YXhuXRNces/WpIwM2OAqT8FsqBM2yRllk7Fo1wiNoPfDmthu2Gad6KZ3g3nhNv/MD/DJ1aPtOj2fpl6mSNibAbAHOHJcN42o55Yh1ttKzEz+Hu4aGswZOX8I5zdZUE6hA6S1yVaumz2orAha8D8gOa5NslleyFsgtZga9HXqFtzo5Ge0oulSZ2InNBXDi6sqgsbcuaoNEsh9mDPAnwRtUOpumMxvhKBEvOM6m/5U2mos4GRpnt3qR9MwMKNGR3Fl11Xw67FJUwG8UNVUT+xFJX/o3tnXG4XqLG3Egsuu71UiT+HTtpSQ4cVjJk+Q3ahjqIB9AeLT3+O8RGzGjhGuvYC0hkaTPN/aN/NPVliWndhjtKzFUlC1ve9qqmKTW6UFJscCo2Kc3y1epSgJe1EeEVlDyJKz3yzR9DSGcOmlfPqPT2twtH/chKZiLHVR5pQike0oi81dXAp6AvpUXTf9GZqLyyuGZhMypHM/d3k++rujWdcdhHlKHkbXrL+DHCJeBDFrUyVpZwfme4Y0woYA5LuTDbgjtZoBPkPBAZqlaRFQRs7mvs7nK+8gr7FyEH40I89sRm0dvsiFOMuYvS/Pua5tMxSQHwO5UFR02Qhr24Ao4ILCSIdakC/+dPzVSIBzbqGapAizvnBTofcOoc5YCowRnAQx0O2xJxrPDlIoiTGK+VmxiTzAxnSnGtewyExOvjCJe+iCen0I/m73Nt2YTEaQHc80PxD2iANaiOqgrnWQ0aeW+fLuovoVml8d/GdkcxYXCg3tXt+tQO9yGkHVBg95MsSmv3KuBJnX3x7rj4/nNygv+p2+fwnQovJ7b697mUDBFr9jQ+kJ98QuidM1/BwkrSi7eGLm1Q9gGp6a6r44cyqF7w8ItpnZL7OqV8ac/9TFHoyWvs4elTTjYCPeVvv3Xzgxslyrz1UE/DPqg5ivPDuf7RkKReBEQ3chtjLJO7UgM7R4mqJZNvGk7/1wEQ9yg6CAeGYn9UheznlEWHs2R5Ktf6KiPJzEhEyjfLWHHEFOH/ddmWOxUEh6YLuDDEMvweg12eewnvop9p1u5WMgkfE9eTJhSH5vKubISiSr2kF72q4Gj8qhJfte1gm6lW/EFKdJlXZzoeP3unxGNrYTuJp5FZThNCrS0bNBQohdQKZlhBmarcOfLrwBQcgwpuJH2RQDEkdE8zEXAxPXQ+6JdV03FzgxCi2i1cPQS02Y7LJhIdhRf+kczd0TlkInjogeXW9LQfbA6Mm4EU0gEa5AH7Kh75j0LfWdjf1EIPozJqj+Tr5bLmgG2aj2OYSeSIml5lLbtkpW4g6yE7PjEB29uCQfoQyhKOnIK9ba/JR6BBiWfmqiCU9vZlxDT2RklbdJMQBqkILoi09EmWa4pu1fc08mD9AV",
    packet_info: {
        linktype: 1
    }

}
```

## Rule

```alert udp any any -> [$HOME_NET,$HTTP_SERVERS] any (msg:\"ET EXPLOIT Possible Apache log4j RCE Attempt - 2021/12/12 Obfuscation Observed M2 (udp) (CVE-2021-44228)\"; content:\"|24 7b|\"; content:\"|24 7b 3a 3a|\"; within:100; fast_pattern; reference:cve,2021-44228; classtype:attempted-admin; sid:2034674; rev:2; metadata:attack_target Server, created_at 2021_12_12, cve CVE_2021_44228, deployment Perimeter, deployment Internal, former_category EXPLOIT, signature_severity Major, tag Exploit, updated_at 2022_01_11;)```

This is all Mullvad wireguard traffic to and from a host on my network.

This section of the message is the section that seems to be tripping the false positive.

> #.^op.D...${6E2/.N.P${::.&.d7...

![image](https://user-images.githubusercontent.com/43767555/227582720-727d7d28-30ea-462b-bec8-6506cdd9b1a7.png)


## Final Thoughts

I have 100% concluded this is mullvad vpn traffic since it is the only thing allowed out from this IP on the firewall.

There is also no inbound rules to this IP to warrant an initial attack inbound either.

I don't think this warrants a fix necesarily. I just thought it was interesting data to wake up to on my home lab.
