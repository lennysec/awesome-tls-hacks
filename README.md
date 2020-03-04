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
  - [Some Open Source Implementations of TLS](#some-open-source-implementations-of-tls)
  - [Glossary](#glossary)

## SSL/TLS Protocol History

| Protocol Name | Release Time | Author | RFC |
| --- | --- | --- | --- |
| SSL 1.0 | N/A | Netscape | N/A |
| SSL 2.0 | 1995 | Netscape | N/A |
| SSL 3.0 | 1996 | Netscape | N/A |
| TLS 1.0 | 1999/01 | IETF TLS Working Group | [RFC 2246](https://tools.ietf.org/html/rfc2246) |
| TLS 1.1 | 2006/04 | IETF TLS Working Group | [RFC 4346](https://tools.ietf.org/html/rfc4346) |
| TLS 1.2 | 2008/08 | IETF TLS Working Group | [RFC 5246](https://tools.ietf.org/html/rfc5246) |
| TLS 1.3 | 2018/08 | IETF TLS Working Group | [RFC 8446](https://tools.ietf.org/html/rfc8446) |

## SSL/TLS Hacks

### Cryptographic Issues

#### CBC Issues

| Attack Name | Published Time | Affected Version | Paper |
| --- | --- | --- | --- |
| Bleichenbacher | 2003/09 | SSL 3.0 | [Klima, Vlastimil, Ondrej Pokorný, and Tomáš Rosa. "Attacking RSA-based sessions in SSL/TLS." International Workshop on Cryptographic Hardware and Embedded Systems. Springer, Berlin, Heidelberg, 2003.](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.304.9703&rep=rep1&type=pdf) |
| BEAST | 2011/05 | SSL 3.0, TLS 1.0 | [Rizzo, Juliano, and Thai Duong. "Here come the xor ninjas." In Ekoparty Security Conference, 2011.](https://nerdoholic.org/uploads/dergln/beast_part2/ssl_jun21.pdf) |
| Lucky Thirteen | 2013/02 | SSL 3.0, TLS 1.0/1.1/1.2 | [Al Fardan, Nadhem J., and Kenneth G. Paterson. "Lucky thirteen: Breaking the TLS and DTLS record protocols." 2013 IEEE Symposium on Security and Privacy. IEEE, 2013.](http://isg.rhul.ac.uk/tls/TLStiming.pdf) |
| POODLE | 2014/10 | SSL 3.0 | [Möller, Bodo, Thai Duong, and Krzysztof Kotowicz. "This POODLE bites: exploiting the SSL 3.0 fallback." Security Advisory (2014).](https://computergeek.nl/wp-content/uploads/2014/10/ssl-poodle.pdf) |
| DROWN | 2016/08 | SSL 2.0 | [Aviram, Nimrod, et al. "DROWN: Breaking TLS Using SSLv2." 25th USENIX Security Symposium (USENIX Security 16). 2016.](https://drownattack.com/drown-attack-paper.pdf) |

#### RC4 Issues

| Attack Name | Published Time | Paper |
| --- | --- | --- |
| Single-byte Bias & Double-byte Bias | 2013/07 | [AlFardan, Nadhem, et al. "On the Security of RC4 in TLS." Presented as part of the 22nd USENIX Security Symposium (USENIX Security 13). 2013.](https://profs.info.uaic.ro/~fltiplea/CC/ABPPS2013.pdf) |
| N/A | 2015/03 | [Garman, Christina, Kenneth G. Paterson, and Thyla Van der Merwe. "Attacks Only Get Better: Password Recovery Attacks Against RC4 in TLS." 24th USENIX Security Symposium (USENIX Security 15). 2015.](https://pdfs.semanticscholar.org/698a/16014ca19866c247348e1f00af48d5b2acfe.pdf) |
| Bar-Mitzva | 2015/03 | [Mantin, Itsik. "Bar-Mitzva Attack: Breaking SSL with 13-Year Old RC4 Weakness." Black Hat Asia (2015).](https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf) |
| N/A | 2015/07 | [Vanhoef, Mathy, and Frank Piessens. "All your biases belong to us: Breaking RC4 in WPA-TKIP and TLS." 24th USENIX Security Symposium (USENIX Security 15). 2015.](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-vanhoef.pdf) |

#### Compression Issues

| Attack Name | Published Time | Paper |
| --- | --- | --- |
| CRIME | 2012/09 | [Rizzo, Juliano, and Thai Duong. "The CRIME attack." Ekoparty Security Conference. 2012.](http://netifera.com/research/crime/CRIME_ekoparty2012.pdf) |
| TIME | 2013/03 | [Be’ery, Tal, and Amichai Shulman. "A perfect CRIME? only TIME will tell." Black Hat Europe 2013 (2013).](https://media.blackhat.com/eu-13/briefings/Beery/bh-eu-13-a-perfect-crime-beery-wp.pdf) |
| BREACH | 2013/03 | [Prado, A., N. Harris, and Y. Gluck. "The BREACH Attack." (2013).](http://breachattack.com/)|

### Implementation Issues

| Attack Name | Published Time | Paper |
| --- | --- | --- |
| OpenSSL Heartbleed | 2014/04 | [Durumeric, Zakir, et al. "The matter of heartbleed." Proceedings of the 2014 conference on internet measurement conference. 2014.](http://conferences2.sigcomm.org/imc/2014/papers/p475.pdf) |
| Triple Handshake | 2014/05 | [Bhargavan, Karthikeyan, et al. "Triple handshakes and cookie cutters: Breaking and fixing authentication over TLS." 2014 IEEE Symposium on Security and Privacy. IEEE, 2014.](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.686.2786&rep=rep1&type=pdf) |
| FREAK | 2015/05 | [Beurdouche, Benjamin, et al. "A messy state of the union: Taming the composite state machines of TLS." 2015 IEEE Symposium on Security and Privacy. IEEE, 2015.](https://prosecco.gforge.inria.fr/personal/karthik/pubs/messy-state-of-the-union-oakland15.pdf) |
| Logjam | 2015/10| [Adrian, David, et al. "Imperfect forward secrecy: How Diffie-Hellman fails in practice." Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security. 2015.](https://weakdh.org/imperfect-forward-secrecy.pdf) |
| SLOTH | 2016/02 | [Bhargavan, Karthikeyan, and Gaëtan Leurent. "Transcript Collision Attacks: Breaking Authentication in TLS, IKE, and SSH." In Network and Distributed System Security Symposium (NDSS). 2016.](https://www.ndss-symposium.org/wp-content/uploads/2017/09/transcript-collision-attacks-breaking-authentication-tls-ike-ssh.pdf) |

## Some Open Source Implementations of TLS

| Implementation | Developed by | Written in | URL |
| --- | --- | --- | --- |
| BoringSSL | Google | C, C++, Go, assembly | [https://boringssl.googlesource.com/boringssl](https://boringssl.googlesource.com/boringssl) |
| Fizz | Facebook | C++ | [https://github.com/facebookincubator/fizz](https://github.com/facebookincubator/fizz) |
| GnuTLS | GnuTLS project | C | [https://www.gnutls.org/](https://www.gnutls.org/) |
| LibreSSL | OpenBSD Project | C, assembly | [https://www.libressl.org/](https://www.libressl.org/) |
| MatrixSSL | PeerSec Networks | C | [https://github.com/matrixssl/matrixssl](https://github.com/matrixssl/matrixssl) |
| OpenSSL | OpenSSL project | C, assembly | [https://github.com/openssl/openssl](https://github.com/openssl/openssl) |
| S2n | Amazon | C | [https://github.com/awslabs/s2n](https://github.com/awslabs/s2n) |
| wolfSSL | wolfSSL | C | [https://github.com/wolfSSL/wolfssl](https://github.com/wolfSSL/wolfssl) |

## Glossary

SSL: Secure Sockets Layer

TLS: Transport Layer Security

IETF: Internet Engineering Task Force

POODLE: Padding Oracle On Downgrade Legacy Encryption

DROWN: Decrypting RSA using Obsolete and Weakened eNcryption

CRIME: Compression Ratio Info-leak Made Easy

TIME: Timing Info-leak Made Easy

BREACH: Browser Reconnaissance & Exfiltration via Adaptive Compression of Hypertext

FREAK: Factoring RSA Export Keys
