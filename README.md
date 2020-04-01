# Awesome SSL/TLS Hacks

## Contents

- [Awesome SSL/TLS Hacks](#awesome-ssltls-hacks)
  - [Contents](#contents)
  - [SSL/TLS Protocol History](#ssltls-protocol-history)
  - [SSL/TLS Hacks](#ssltls-hacks)
    - [Cryptographic Issues](#cryptographic-issues)
      - [CBC Issues](#cbc-issues)
      - [RC4 Issues](#rc4-issues)
      - [Compression Issues](#compression-issues)
    - [Implementation Issues](#implementation-issues)
  - [Some Open Source Implementations of SSL/TLS](#some-open-source-implementations-of-ssltls)
  - [OpenSSL Version History](#openssl-version-history)
  - [Vulnerabilities](#vulnerabilities)
    - [Fizz Vulnerabilities](#fizz-vulnerabilities)
    - [OpenSSL Vulnerabilities](#openssl-vulnerabilities)
  - [Tools](#tools)
    - [Fuzzing](#fuzzing)
    - [Programing](#programing)
  - [Glossary](#glossary)

## SSL/TLS Protocol History

| Protocol Name | Release Date | Author | RFC |
| --- | --- | --- | --- |
| SSL 1.0 | N/A | Netscape | N/A |
| SSL 2.0 | 1995 | Netscape | N/A |
| SSL 3.0 | 1996 | Netscape | N/A |
| TLS 1.0 | 1999-01 | IETF TLS Working Group | [RFC 2246](https://tools.ietf.org/html/rfc2246) |
| TLS 1.1 | 2006-04 | IETF TLS Working Group | [RFC 4346](https://tools.ietf.org/html/rfc4346) |
| TLS 1.2 | 2008-08 | IETF TLS Working Group | [RFC 5246](https://tools.ietf.org/html/rfc5246) |
| TLS 1.3 | 2018-08 | IETF TLS Working Group | [RFC 8446](https://tools.ietf.org/html/rfc8446) |

## SSL/TLS Hacks

### Cryptographic Issues

#### CBC Issues

| <div style="width:130px">Attack Name</div> | <div style="width:100px">Published Date</div> | Affected Version | Paper |
| --- | --- | --- | --- |
| Bleichenbacher | 2003-09 | SSL 3.0 | [Klima, Vlastimil, Ondrej Pokorný, and Tomáš Rosa. "Attacking RSA-based sessions in SSL/TLS." International Workshop on Cryptographic Hardware and Embedded Systems. Springer, Berlin, Heidelberg, 2003.](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.304.9703&rep=rep1&type=pdf) |
| BEAST | 2011-05 | SSL 3.0, TLS 1.0 | [Rizzo, Juliano, and Thai Duong. "Here come the xor ninjas." In Ekoparty Security Conference, 2011.](https://nerdoholic.org/uploads/dergln/beast_part2/ssl_jun21.pdf) |
| Lucky Thirteen | 2013-02 | SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2 | [Al Fardan, Nadhem J., and Kenneth G. Paterson. "Lucky thirteen: Breaking the TLS and DTLS record protocols." 2013 IEEE Symposium on Security and Privacy. IEEE, 2013.](http://isg.rhul.ac.uk/tls/TLStiming.pdf) |
| POODLE | 2014-10 | SSL 3.0 | [Möller, Bodo, Thai Duong, and Krzysztof Kotowicz. "This POODLE bites: exploiting the SSL 3.0 fallback." Security Advisory (2014).](https://computergeek.nl/wp-content/uploads/2014/10/ssl-poodle.pdf) |
| DROWN | 2016-08 | SSL 2.0 | [Aviram, Nimrod, et al. "DROWN: Breaking TLS Using SSLv2." 25th USENIX Security Symposium (USENIX Security 16). 2016.](https://drownattack.com/drown-attack-paper.pdf) |

#### RC4 Issues

| <div style="width:130px">Attack Name</div> | <div style="width:100px">Published Date</div> | Paper |
| --- | --- | --- |
| Single-byte Bias & Double-byte Bias | 2013-07 | [AlFardan, Nadhem, et al. "On the Security of RC4 in TLS." Presented as part of the 22nd USENIX Security Symposium (USENIX Security 13). 2013.](https://profs.info.uaic.ro/~fltiplea/CC/ABPPS2013.pdf) |
| N/A | 2015-03 | [Garman, Christina, Kenneth G. Paterson, and Thyla Van der Merwe. "Attacks Only Get Better: Password Recovery Attacks Against RC4 in TLS." 24th USENIX Security Symposium (USENIX Security 15). 2015.](https://pdfs.semanticscholar.org/698a/16014ca19866c247348e1f00af48d5b2acfe.pdf) |
| Bar-Mitzva | 2015-03 | [Mantin, Itsik. "Bar-Mitzva Attack: Breaking SSL with 13-Year Old RC4 Weakness." Black Hat Asia (2015).](https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf) |
| N/A | 2015-07 | [Vanhoef, Mathy, and Frank Piessens. "All your biases belong to us: Breaking RC4 in WPA-TKIP and TLS." 24th USENIX Security Symposium (USENIX Security 15). 2015.](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-vanhoef.pdf) |

#### Compression Issues

| <div style="width:130px">Attack Name</div> | <div style="width:100px">Published Date</div> | Paper |
| --- | --- | --- |
| CRIME | 2012-09 | [Rizzo, Juliano, and Thai Duong. "The CRIME attack." Ekoparty Security Conference. 2012.](http://netifera.com/research/crime/CRIME_ekoparty2012.pdf) |
| TIME | 2013-03 | [Be’ery, Tal, and Amichai Shulman. "A perfect CRIME? only TIME will tell." Black Hat Europe 2013 (2013).](https://media.blackhat.com/eu-13/briefings/Beery/bh-eu-13-a-perfect-crime-beery-wp.pdf) |
| BREACH | 2013-03 | [Prado, A., N. Harris, and Y. Gluck. "The BREACH Attack." (2013).](http://breachattack.com/)|

### Implementation Issues

| <div style="width:130px">Attack Name<div> | <div style="width:100px">Published Date</div> | Paper |
| --- | --- | --- |
| OpenSSL Heartbleed | 2014-04 | [Durumeric, Zakir, et al. "The matter of heartbleed." Proceedings of the 2014 conference on internet measurement conference. 2014.](http://conferences2.sigcomm.org/imc/2014/papers/p475.pdf) |
| Triple Handshake | 2014-05 | [Bhargavan, Karthikeyan, et al. "Triple handshakes and cookie cutters: Breaking and fixing authentication over TLS." 2014 IEEE Symposium on Security and Privacy. IEEE, 2014.](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.686.2786&rep=rep1&type=pdf) |
| FREAK | 2015-05 | [Beurdouche, Benjamin, et al. "A messy state of the union: Taming the composite state machines of TLS." 2015 IEEE Symposium on Security and Privacy. IEEE, 2015.](https://prosecco.gforge.inria.fr/personal/karthik/pubs/messy-state-of-the-union-oakland15.pdf) |
| Logjam | 2015-10| [Adrian, David, et al. "Imperfect forward secrecy: How Diffie-Hellman fails in practice." Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security. 2015.](https://weakdh.org/imperfect-forward-secrecy.pdf) |
| SLOTH | 2016-02 | [Bhargavan, Karthikeyan, and Gaëtan Leurent. "Transcript Collision Attacks: Breaking Authentication in TLS, IKE, and SSH." In Network and Distributed System Security Symposium (NDSS). 2016.](https://www.ndss-symposium.org/wp-content/uploads/2017/09/transcript-collision-attacks-breaking-authentication-tls-ike-ssh.pdf) |

## Some Open Source Implementations of SSL/TLS

| Implementation | Initial release | Developed by | Written in |
| --- | --- | --- | --- |
| [OpenSSL](https://github.com/openssl/openssl) | 1998-12 | OpenSSL Project | C, Assembly |
| [GnuTLS](https://gitlab.com/gnutls/gnutls) | 2000-03 | GnuTLS Project | C |
| [wolfSSL](https://github.com/wolfSSL/wolfssl) | 2011-02 | wolfSSL | C |
| [BoringSSL](https://github.com/google/boringssl) | 2014-06 | Google | C, C++, Go, Assembly |
| [s2n](https://github.com/awslabs/s2n) | 2014-06 | Amazon | C |
| [LibreSSL](https://www.libressl.org/) | 2014-07 | OpenBSD Project | C, Assembly |
| [MatrixSSL](https://github.com/matrixssl/matrixssl) | 2015-03 | PeerSec Networks | C |
| [Fizz](https://github.com/facebookincubator/fizz) | 2018-06 | Facebook | C++ |

## OpenSSL Version History

| Major version | Original release date | Last minor version | Last update date |
| --- | --- | --- | --- |
| 0.9.1 | 1998-12-23 | 0.9.1c | 1998-12-23 |
| 0.9.2 | 1999-03-22 | 0.9.2b | 1999-04-06 |
| 0.9.3 | 1999-05-25 | 0.9.3a | 1999-05-27 |
| 0.9.4 | 1999-08-09 | 0.9.4 | 1999-08-09 |
| 0.9.5 | 2000-02-28 | 0.9.5a | 2000-04-01 |
| 0.9.6 | 2000-09-24 | 0.9.6m | 2004-03-17 |
| 0.9.7 | 2002-12-31 | 0.9.7m | 2007-02-23 |
| 0.9.8 | 2005-07-05 | 0.9.8zh | 2015-12-03 |
| 1.0.0 | 2010-03-29 | 1.0.0t | 2015-12-03 |
| 1.0.1 | 2012-03-14 | 1.0.1u | 2016-09-22 |
| 1.0.2 | 2015-01-22 | 1.0.2u | 2019-12-20 |
| 1.1.0 | 2016-08-25 | 1.1.0l | 2019-09-10 |
| 1.1.1 | 2018-09-11 | 1.1.1f | 2020-03-31 |

## Vulnerabilities

### Fizz Vulnerabilities

| <div style="width:120px">CVE-ID</div> |  <div style="width:120px">Disclosure date</div> | Type | Analysis |
| --- | --- | --- | --- |
| CVE-2019-3560 | 2019-02-26 | Server Side DoS | [Facebook Fizz integer overflow vulnerability (CVE-2019-3560)](https://securitylab.github.com/research/facebook-fizz-CVE-2019-3560) |
| CVE-2019-11924 | 2019-08-09 | Server Side Memory Leak | [Facebook Fizz memory leak vulnerability (CVE-2019-11924) reproduce and analysis](https://lenny233.github.io/2020/03/30/fizz-memory-leak-analysis/) |

### OpenSSL Vulnerabilities

## Tools

### Fuzzing

tlsfuzzer  
<https://github.com/tomato42/tlsfuzzer>

boofuzz  
<https://github.com/jtpereyda/boofuzz>

Fuzzowski  
<https://github.com/jtpereyda/boofuzz>

AFLNet  
<https://github.com/jtpereyda/boofuzz>

### Programing

The New Illustrated TLS Connection  
<https://tls13.ulfheim.net/>

Python built-in TLS wrapper  
<https://docs.python.org/3.8/library/ssl.html>

TLS implementation in pure python  
<https://github.com/tomato42/tlslite-ng>

Scapy: the Python-based interactive packet manipulation program & library  
<https://github.com/secdev/scapy/>

## Glossary

| Abbreviation | Explanation |
| --- | --- |
| SSL | Secure Sockets Layer |
| TLS | Transport Layer Security |
| IETF | Internet Engineering Task Force |
| POODLE | Padding Oracle On Downgrade Legacy Encryption |
| DROWN | Decrypting RSA using Obsolete and Weakened eNcryption |
| CRIME | Compression Ratio Info-leak Made Easy |
| TIME | Timing Info-leak Made Easy |
| BREACH | Browser Reconnaissance & Exfiltration via Adaptive Compression of Hypertext |
| FREAK | Factoring RSA Export Keys |
