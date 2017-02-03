drops
=====

[dr]:ops -- dead drops for ops

A _p2p_ transport network for opmsg end2end encrypted messages.

* p2p architecture that doesnt require central servers
* almost no meta data
* allows for secure, anonymous communication
* use the same _opmsg_ setup that you use for email
* IPv6 ready
* be part of the global opmsg p2p or a private local p2p with your friends

Build
-----

_drops_ requires  _OpenSSL_. You may use the default installed openssl of your
system or create your own libressl install (recommended).

The compilation requires a C++ compiler that supports `-std=c++11`.
This can be configured with e.g. `make CXX=eg++ LD=eg++` on _OpenBSD_.

This project supports both `BN_GENCB_new` and `BN_GENCB` for big number
generation. To disable `BN_GENCB_new`, set `HAVE_BN_GENCB_NEW` to false:
`make DEFS=-DHAVE_BN_GENCB_NEW=0`. So on _OpenBSD_, you would run
`make CXX=eg++ LD=eg++ DEFS=-DHAVE_BN_GENCB_NEW=0`. On _OSX_ you should install
your own _OpenSSL_, as Apple marks _OpenSSL_ as deprecated in favor of their own
crypto libs. You may also set all these options in the `Makefile`.

It successfully builds on _Linux_, _OSX_, _OpenBSD_ and probably a lot of others
(_Solaris_, _FreeBSD_,...).

If you use your own openssl install, adjust the library paths inside the `Makefile`.

```
$ cd src
$ make
[...]
$ make install

```
Decide yourself where to place the `dropsd` binary. It could be copied to `~/.drops/bin` .

Run
---

Edit `~/.drops/global/config` to set at least the filters you need, to catch the opmsg personas
that you own and maybe the other self-explaining parameters.

Then you simply run
```
$ dropsd
```
If you are missing a `nodes` file in `~/.drops/global`, you may specify the `--bootstrap`
parameter to connect to your first node.

To send an opmsg to the network you would:

```
$ opmsg -E 1122334455667788 -o ~/.drops/global/outq/1.opmsg
```

and its automatically delivered. Filenames must end in `.opmsg` for safety reasons.
**Note: Since drops is a p2p network, everyone would get this message. So make sure your
opmsg setup is correct, you are not using null ciphers or dirty personas from test setups and alike.**

Every opmsg that passes the `filter=` from the config file, will be placed into `~/.drops/inq`
where you can decrypt it using `opmsg -D`.

You have to have a clock thats set more or less to the correct time (a few hours shift
dont matter). (Will explain in a dedicated chapter later, This is just beta test now).

License
-------

The sources in the `src` directory are licensed under the GPL.

Everything inside the `non-commercial` directory must not be used when you:

* make revenue based on the drops source or the drops p2p network or its users, or
* offer products or services based on any drops components in this repository

You are not allowed to use or distribute any of the keying material (ca.pem, cert.pem, key.pem)
for or with any of your products or services that you offer.


Meta Data
---------

(TODO)


Local drops
-----------

(TODO)

