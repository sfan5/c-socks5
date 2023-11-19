c-socks5
========
**A small SOCKS5 proxy written in C**

Notable features:
* Happy Eyeballs (RFC 6555)
* no UDP support
* scalable async design

Libs needed: [c-ares](https://c-ares.haxx.se/)

Building the thing: `make RELEASE=1`

Running the thing:
* `./c-socks5`
* basic options see `--help`
* config file for everything else, full documentation + examples in `c-socks5.conf`
