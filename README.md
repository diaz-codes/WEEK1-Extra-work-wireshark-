# Wireshark SOC Analyst Labs

Hands-on network traffic analysis completed as part of the **NetworkWalks Extra: Wireshark project** (Labs 3 to 8). In each lab I acted as a SOC analyst: capture the traffic, find the evidence, and explain what happened.

> All labs ran in a browser-based, simulated environment. No real networks were captured or tested.

## Skills practised

- Capturing and filtering traffic in Wireshark
- Identifying attackers, targets and attack types from packet evidence
- Reading unencrypted traffic with **Follow TCP Stream**
- Spotting port scans, brute force attempts and credential leaks
- Analysing VoIP traffic (SIP signalling and RTP audio)

## Lab summaries

| Lab | Scenario | What I did | Key tools and filters |
|---|---|---|---|
| 3 | Identify the attacker's IP | Found one host sending a long block of SYN packets to many ports. Worked out which ports were open (SYN, ACK) and closed (RST, ACK). Conclusion: **port scan**. | `tcp.flags.syn == 1`, `ip.src == <ip>`, Statistics > Conversations |
| 4 | Follow TCP Stream | Found a plain-text office chat on a non-web port and read the whole conversation, including shared credentials. | `tcp.port == <port>`, `tcp.stream eq <n>`, Follow > TCP Stream |
| 5 | Follow TCP Stream, part 2 | Found a secret hidden in an HTML comment on an intranet page and a file downloaded from `/download/`. | `http.request.method == "GET"`, `http.request.uri contains "/download/"` |
| 6 | HTTP plain text credentials | Showed that a sign-in over HTTP sends the username and password in readable form inside a POST request. | `http.request.method == "POST"`, HTML Form URL Encoded |
| 7 | Brute force catch | Found one host guessing passwords against an FTP server, counted the failed logins and found the guess that worked. Conclusion: **brute force attack**. | Protocol Hierarchy, `ftp.request`, `ftp.response.code == 530` / `230` |
| 8 | VoIP call replay | Located the call, identified caller and receiver from the SIP INVITE, and replayed the RTP audio. | `sip`, `rtp`, Telephony > VoIP Calls > Play Streams |

## Filter cheat sheet

| Goal | Filter |
|---|---|
| Traffic from a host | `ip.src == 192.168.10.66` |
| Traffic to a host | `ip.dst == 192.168.10.20` |
| Connection attempts (SYN) | `tcp.flags.syn == 1` |
| Closed-port replies (RST) | `tcp.flags.reset == 1` |
| One conversation | `tcp.stream eq 5` |
| Web page requests | `http.request.method == "GET"` |
| Form submissions | `http.request.method == "POST"` |
| FTP login failures | `ftp.response.code == 530` |
| FTP login success | `ftp.response.code == 230` |
| VoIP call setup | `sip.Method == "INVITE"` |

Operators: `==` equals, `&&` and, `!` not, `contains` text search. Method names such as `GET` and `POST` must be in capitals.

## Key lessons

- Traffic sent without encryption (HTTP, FTP, plain-text chat, unencrypted VoIP) can be read by anyone who captures it. Use HTTPS, SSH/SFTP and encrypted calling.
- Never leave secrets in page source. HTML comments are hidden in the browser but visible on the wire.
- Port scans show up as one source sending SYNs to many ports, and brute force attacks as many failed logins from one source in a short time.
- Wireshark filters turn thousands of packets into a short list of evidence.

