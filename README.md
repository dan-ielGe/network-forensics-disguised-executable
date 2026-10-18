# Network Forensics: A Windows Executable Disguised as a PNG

An investigation of a supplied educational packet capture using **Wireshark**, **HTTP object recovery**, and **static file examination**.

**Main finding:** an object downloaded as `444444.png` and labelled `image/png` contained a 32-bit Windows PE executable. A later TLS connection from the same client provided additional network indicators, but the capture alone does not prove execution or command-and-control activity.

## My contribution

I performed the hands-on network investigation, examined the HTTP and TLS evidence, exported the candidate file, and checked its format and hash. The screenshots document my analysis. This repository presents my individual work on this investigation.

The packet capture was supplied as educational material. I did not create the capture or the traffic it contains. The capture and recovered executable are not included in this repository.

## Tools and techniques

| Tool or technique | Purpose |
|---|---|
| Wireshark | Packet filtering, stream correlation, HTTP export, TLS and certificate inspection |
| SHA-256 | Capture-copy comparison and recovered-file identification |
| `file` | Identification from file content |
| `xxd` | Examination of the starting bytes |
| HTTP and TLS correlation | Comparison of endpoints, frame numbers, and timing |

## Findings at a glance

| Indicator | Finding |
|---|---|
| Client | `10.1.29.101` |
| HTTP server | `5.61.27.159:80` |
| HTTP Host | `alphaenergyeng.com` |
| Requested object | `/wp-content/uploads/2020/01/ahead/444444.png` |
| Declared content type | `image/png` |
| HTTP Content-Length | `475136` bytes |
| Recovered-file type | PE32 executable (GUI), Intel 80386, for MS Windows, 4 sections |
| Starting bytes | `4D 5A` (`MZ`) |
| Later TLS endpoint examined | `68.1.115.106:443` |
| SNI in selected Client Hello | Not present |
| Certificate Common Name | `gaevietovp.mobi` |

**Recovered-file SHA-256**

```text
56ee803fa903ab477f939b3894af6771aebf0138abe38ae8e3c41cf96bbb0f2a
```

These addresses and names are historical indicators from the capture. They are not claims about the current ownership or behaviour of those endpoints.

## 1. Preserve and profile the evidence

I compared SHA-256 hashes of the original capture and working copy. Matching values supported byte-for-byte equivalence. I also reviewed capture properties before filtering.

The capture contains **74,404 packets** and spans approximately **2 hours, 42 minutes, 55 seconds** on **29 January 2020**. Some screenshots show local or relative time. UTC values and relative differences are identified explicitly below.

![Original and working capture SHA-256 values]<img width="1513" height="145" alt="01-capture-hashes" src="https://github.com/user-attachments/assets/6428bc39-b50e-4685-bca1-e83c0c3ecc0d" />

*Figure 1. Matching hashes for the original and working capture.*

![Capture properties](screenshots/02-capture-properties.png)
*Figure 2. Packet count, capture duration, and capture metadata.*

## 2. Locate possible image transfers

I started with HTTP requests:

```wireshark
http.request
```

![HTTP traffic overview](screenshots/03-http-overview.png)
*Figure 3. Initial HTTP request review before narrowing the search.*

I then searched common image extensions:

```wireshark
http.request && (
    http.request.uri contains ".png" ||
    http.request.uri contains ".jpg" ||
    http.request.uri contains ".jpeg" ||
    http.request.uri contains ".gif" ||
    http.request.uri contains ".bmp" ||
    http.request.uri contains ".ico" ||
    http.request.uri contains ".webp"
)
```

![Image request results](screenshots/04-image-requests.png)
*Figure 4. One request for `444444.png` and two requests for `/favicon.ico`.*

This was a candidate-discovery filter. Extensions can be misleading, extensionless objects can be missed, and encrypted transfers are outside this filter's visibility.

## 3. Establish the HTTP context

I isolated the candidate:

```wireshark
http.request.uri contains "444444.png"
```

| Field | Observation |
|---|---|
| Request frame | `2498` |
| Client connection | `10.1.29.101:49689` |
| Server connection | `5.61.27.159:80` |
| HTTP Host | `alphaenergyeng.com` |
| User-Agent | `Haskel` |
| Response status | `200 OK` |
| Content-Disposition | `attachment; filename="444444.png"` |
| Content-Type | `image/png` |
| Content-Length | `475136` |

![Candidate HTTP request](screenshots/05-candidate-request.png)
*Figure 5. Request details associated with the apparent PNG download.*

I used **Follow TCP Stream** to correlate the request and response within the same connection.

![HTTP request and response headers](screenshots/06-http-stream.png)
*Figure 6. The server presented the object as a PNG image.*

The Host header establishes what hostname the client requested. It does not establish the operator's identity. The unusual User-Agent was a supporting observation, not proof of malware.

## 4. Identify the content mismatch

A PNG should start with:

```text
89 50 4E 47 0D 0A 1A 0A
```

The response body instead started with:

```text
4D 5A 90 00
```

![Executable signature after HTTP image headers](screenshots/07-file-signature.png)
*Figure 7. `MZ` appears at the start of the response body despite the PNG metadata.*

The mismatch justified extracting the object for further examination. `MZ` alone is insufficient to establish a complete PE structure; the content-based file identification below provided additional support.

## 5. Recover and examine the file

I used **File → Export Objects → HTTP** to recover the candidate object. The export list associated it with `alphaenergyeng.com` and displayed an approximate size of **475 kB**.

![HTTP object export](screenshots/08-http-object-export.png)
*Figure 8. The candidate object selected for export.*

Static checks used the following commands:

```bash
chmod a-x 444444.png
file 444444.png
xxd -l 64 444444.png
sha256sum 444444.png
```

![File identification and hash](screenshots/09-static-file-checks.png)
*Figure 9. `file` identifies a PE32 Windows executable; the hex dump shows `MZ`, and the final successful command records SHA-256.*

The screenshot also retains an initial mistyped hash command and its error. The subsequent successful command supplies the recorded hash.

The file-format result supports an executable transferred under an image name and MIME type. The hash identifies the recovered bytes; it does not prove maliciousness. No execution of the recovered file was required for this finding.

## 6. Review encrypted communication

I reviewed decoded TLS traffic and TCP conversation statistics:

```wireshark
tls
```

![TLS conversation overview](screenshots/10-tls-conversations.png)
*Figure 10. TCP conversation statistics used to review encrypted connections.*

I then examined traffic to one endpoint and selected a connection:

```wireshark
ip.addr == 68.1.115.106 && tls
```

```wireshark
ip.addr == 68.1.115.106 && tcp.port == 49697
```

![Selected TLS connection](screenshots/11-selected-tls-connection.png)
*Figure 11. TLS connection between `10.1.29.101:49697` and `68.1.115.106:443`.*

### Client Hello and SNI

```wireshark
ip.addr == 68.1.115.106 && tcp.port == 49697 &&
tls.handshake.type == 1
```

![Client Hello extensions without SNI](screenshots/12-client-hello-no-sni.png)
*Figure 12. The selected Client Hello contains no `server_name` extension.*

No hostname was supplied through SNI in this handshake. This absence does not independently establish malicious activity.

### Captured DNS evidence

```wireshark
dns.a == 68.1.115.106
```

![DNS search with no matching answers](screenshots/13-dns-search.png)
*Figure 13. No packets matched the DNS A-record answer filter.*

No DNS A-record answer linking a hostname to this IP was found using this filter. Cached resolution, activity outside the capture, or other resolution methods remain possible. The certificate name discussed next was not obtained from DNS or SNI.

## 7. Examine the TLS certificate

```wireshark
ip.addr == 68.1.115.106 && tcp.port == 49697 &&
tls.handshake.type == 11
```

![TLS certificate in frame 3174](screenshots/14-certificate-overview.png)
*Figure 14. Certificate message presented by the selected TLS server.*

![Expanded certificate issuer](screenshots/15-certificate-issuer.png)
*Figure 15. Issuer fields, including Common Name `gaevietovp.mobi`.*

![Expanded certificate subject](screenshots/18-certificate-subject.png)
*Figure 16. Subject fields, including Common Name `gaevietovp.mobi`.*

![Certificate validity dates](screenshots/16-certificate-validity.png)
*Figure 17. Certificate validity dates shown in UTC.*

| Certificate field | Observation |
|---|---|
| Subject Common Name | `gaevietovp.mobi` |
| Subject country | `ES` |
| Subject organisational unit | `Dobubaexo Boolkedm Bmuw` |
| Issuer Common Name | `gaevietovp.mobi` |
| Serial number | `0x0a83` |
| Signature algorithm | `sha256WithRSAEncryption` |
| Not Before | `2020-01-27 22:35:20 UTC` |
| Not After | `2021-01-27 04:45:24 UTC` |

The capture date falls within this validity period. That verifies the date relationship only, not trust-chain validity. Certificate fields are identity claims; they do not identify the human operator. Matching Common Names do not by themselves prove that a certificate is self-signed.

## 8. Correlate the events

```wireshark
frame.number == 2498 ||
frame.number == 3173 ||
frame.number == 3174
```

| Frame | Relative capture time | Event |
|---|---:|---|
| `2498` | `107.866461 s` | Client requests `444444.png` |
| `3173` | `513.871330 s` | Client sends the selected TLS Client Hello |
| `3174` | `513.986818 s` | Server sends its handshake, including the certificate |

![Selected HTTP and TLS events](screenshots/17-event-correlation.png)
*Figure 18. Selected event packets. The screenshot's display order differs from chronological order; the table above orders the events by frame and time.*

The selected Client Hello occurred approximately **406 seconds** after the file request. The same client and event order make the connection relevant for investigation. They do not prove that the executable initiated it.

## Conclusion

The investigation established a concrete file-format mismatch: **a Windows PE32 executable was transferred as `444444.png` with `Content-Type: image/png`**.

The later TLS connection supplied further indicators, including `68.1.115.106` and the certificate name `gaevietovp.mobi`. Establishing execution or a causal connection would require additional evidence, such as endpoint process records or memory analysis.

### What the evidence does not establish

- Whether the recovered executable ran on the client.
- A confirmed malware family or its behaviour.
- The contents of encrypted application traffic.
- A confirmed command-and-control relationship.
- The identity or location of the operator.

## Repository contents

- `README.md` — methods, screenshots, findings, and limitations.
- `screenshots/` — analysis screenshots with image metadata removed.

The repository contains documentation and screenshots only. The supplied PCAP, executable, assignment specification, student identifiers, and private demonstration links are excluded.
