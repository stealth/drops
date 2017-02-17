drops
=====

**[dr]:ops -- dead drops for ops**

A _p2p_ transport network for [opmsg end2end encrypted messages](https://github.com/stealth/opmsg).
If you are new to _opmsg_, click the link for more info and how to set it up.

* p2p architecture that doesnt require central servers
* almost no meta data
* allows for secure, anonymous communication
* no more secret court orders to take down your favorite mail provider
* use the same _opmsg_ setup that you use for email
* Interconnects IPv4 and IPv6 space
* be part of the global opmsg p2p or a private local p2p with your friends


License
-------

The sources in the `src` directory are licensed under the GPL.

Everything inside the `non-commercial` directory must not be used when you:

* make revenue based on the drops source or the drops p2p network or its users, or
* offer products or services based on any drops components in this repository

You are not allowed to use or distribute any of the keying material (ca.pem, cert.pem, key.pem)
for or with any of your products or services that you offer.


Build
-----

*Note: drops is in the beta testing phase. There are easier things than to
get a p2p network flying and tested. For this reason, expect some changes
to the commandline/config options. Always check your local config against
changes of the template in `non-commercial/config` and do a `make clean`
before `make` after a pull.*

_drops_ requires  _OpenSSL_. You may use the default installed openssl of your
system or create your own [libressl install](https://github.com/libressl-portable/portable) (recommended).

The compilation requires a C++ compiler that supports `-std=c++11`.
This can be configured with e.g. `make CXX=eg++ LD=eg++` on _OpenBSD_.

On _OSX_ you should install your own _OpenSSL_, as Apple marks _OpenSSL_ as deprecated in favor of their own
crypto libs. You may also set all the required options in the `Makefile`.

It successfully builds on _Linux_, _OSX_, _OpenBSD_ and probably a lot of others
(_Solaris_, _FreeBSD_,...).

If you use your own openssl install, adjust the library paths inside the `Makefile`.

```
$ cd src
$ make clean; make
[...]
$ make install

```
Decide yourself where to place the `dropsd` binary. It could be copied to `~/.drops/bin` .

Run
---

```
$ dropsd -h

./dropsd: invalid option -- 'h'
Usage: dropsd   [--confdir dir] [--laddr] [--lport] [--laddr6] [--lport6]
                [--newlocal] [-T tag] [--bootstrap node] [--sni name]

        --confdir,      -c      (must come first) defaults to ~/.drops
        --laddr,        -l      local IPv4 address to bind to (default any)
        --lport,        -p      local TCPv4 port (default 7350)
        --laddr6,       -L      local IPv6 address to bind to (default any)
        --lport6,       -P      local TCPv6 port (default 7350)
        --newlocal,     -N      initially set up a new local drops
        --tag,          -T      drops tag (defaults to 'global')
        --sni,          -S      SNI to use in connects (defaults to 'drops.v2')
        --bootstrap,    -B      bootstrap node if node file is empty and not initial local dropsd

```

Edit `~/.drops/global/config` to set at least the filters you need, to catch the _opmsg_ personas
that you own and maybe the other self-explaining parameters. Its ok to not have any filters in place,
in which case you just volunteer to forward drops messages.
The address and port binding should work for most installations. Make sure your firewall rules allow direct connection to the
Internet and preferably also inbound to your local port. Most cable modems have NAT rules
that automatically forward ports to where connections were originated. So the generic setup
should work in most cases.

Then you simply run:

```
$ dropsd

drops: version=0.12 -- (C) 2017 Sebastian Krahmer https://github.com/stealth/drops

drops: Bits of today=5048 id=d34f22641a1594b62e25bf4833245ad7 tag=global
drops: laddr=0.0.0.0 lport=7350
drops: laddr6=:: lport6=7350
drops: Going background.

```
If you have a missing or damaged `nodes` file in `~/.drops/global`, you may specify the `--bootstrap`
parameter to connect to your first node:

```
$ dropsd --bootstrap [104.197.174.219]:7350
[...]
```

The IP above is a bootstrap node that I have set up so you can test it right away.

To send an opmsg to the network you would:

```
$ opmsg -E 1122334455667788 -o ~/.drops/global/outq/1.opmsg
```

and its automatically delivered. Filenames must end in `.opmsg` for safety reasons.
**Note: Since drops is a p2p network, everyone would get this message. So make sure your
opmsg setup is correct, you are not using null ciphers or dirty personas from test setups and alike.**

Every opmsg that passes the `filter=` from the config file, will be placed into `~/.drops/global/inq`
where you can decrypt it using `opmsg -D`. Messages in transit and which are not for you
may be listed in `~/.drops/global/flying`.

You have to have a clock thats set more or less to the correct time (a few hours shift
dont matter). Clock accuracy is required as the _drops_ network checks so called _Submit-Keys_
for each message. These are unique RSA-keys wich are increasing one bit in size each day (the `Bits of today=`).
This way _drops_ messages older than 10 days vanish from the p2p network and _drops_ becomes more resistant against
DoS attacks.

The log can be found in `~/.drops/global/log.txt`. It shows your peers and errors that
might occur. Do not be worried about handshake errors or disappearing peers. This is
not uncommon in p2p networks.


Meta Data
---------

opmsg already protects the content of your messages when using it with email. However, it cannot
protect the mail header since this meta data is required for routing the mail to its
destination. A global observer may build a graph of addresses and timestamps to link
groups of people to each other and to gather intelligence on it. Thats a well known problem
for email and most messenging systems that exist today -- even a problem of the most popular ones.

Not so with _drops_.

The more people use the _drops_ p2p network, the difficulter it becomes to determine:

* Who actually submitted a message into the network
* Who is reading it
* Which of the many opmsg personas belong to which real person
* How many real persons are really participating

If all _drops_ users follow the _opmsg_ rules of setting up dedicated personas
for each communication peer, a global observer will only see 1:1 pairings in
the surveillance graph, along with cloaked timestamps. He cannot learn
which group of people belongs to each other. At most he can see how strong
this link may be due to the amount of messages. Thats why you would throw away
_opmsg_ personas regularily. **Its also recommended to create dedicated
personas for the _drops_ network and to not use your existing personas
that you used for mail**. To make it easier to remember, assign a name that
reflects it:

```

$ opmsg --newecp --name jimmy@drops

opmsg: version=1.75 -- (C) 2016 opmsg-team: https://github.com/stealth/opmsg

opmsg: creating new EC persona (curve brainpoolP512t1)



opmsg: Successfully generated persona with id
opmsg: 233054f68bfc8e57 332a29b7011be2c4 01c51ac318d91515 7f034712253b9211
opmsg: Tell your remote peer to add the following pubkey like this:
opmsg: opmsg --import --phash sha256 --name 'jimmy@drops'

-----BEGIN PUBLIC KEY-----
MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDgOBggAEabqKWhf4Qvj8BWz6jO4MsKjd
AvSAHdM2g6H1/ppstX3PNvhQlrVKexmUVPp4fxKInKaree8pnK4TpgpYTbtPzHxP
Rtz/h773kxKqk5LV+K+5RtxFpo6vZB4zxDY0ogPUF+K0hR5M7CcMRhhU9OjyewXA
64IMbUD/Jfw9NXrliZ0=
-----END PUBLIC KEY-----

opmsg: Check (by phone, otr, twitter, id-selfie etc.) that above id matches
opmsg: the import message from your peer.
opmsg: AFTER THAT, you can go ahead, safely exchanging op-messages.

opmsg: SUCCESS.

```

Jimmys peer, who is importing this persona **and linking it to their own persona**
may then submit _drops_ messages to Jimmy (given that Jimmy and his peer set up
the drops):

```
$ opmsg -E 233054f68bfc8e57 -o ~/.drops/global/outq/1.opmsg
[...]
```
Which Jimmy will find in his `~/.drops/global/inq`.

Local drops
-----------

There may be circumstances when you want to use _drops_ but dont want to submit
your messages to be globally visible. For such reasons local _drops_ exist:

```
$ dropsd -N

drops: version=0.12 -- (C) 2017 Sebastian Krahmer https://github.com/stealth/drops

drops: Success setting up new local drops with tag 87cb0b3623b7cdcc696e8f172b06820a

drops: You execute: dropsd -T 87cb0b3623b7cdcc696e8f172b06820a
drops: All others execute: dropsd -T 87cb0b3623b7cdcc696e8f172b06820a -B [yourip]:yourport

```

Local _drops_ are using different client/server certificates than global ones.
The keys are located within the _~/.drops/local/<TAG>_ directory (`~/.drops/local/87cb0b3623b7cdcc696e8f172b06820a/` in this
example).
You may set up your own CA and replace the .pem files
with your own to entirely close your local _drops_ to persons who are in possession of these keys.
Otherwise the above tag `87cb0b3623b7cdcc696e8f172b06820a` is the ticket to enter your local _drops_
and it is unique to each new local _drops_.
Your friends would issue `dropsd -T 87cb0b3623b7cdcc696e8f172b06820a -B [yourip]:yourport` once
you started the newly generated _drops_ via `dropsd -T 87cb0b3623b7cdcc696e8f172b06820a`
just as it reads above. The reason you explicitely need to start the new instance after
you generated it with `-N` is that you have time to switch the key material for the new
local _drops_ as mentioned above. As there doesnt exist any _nodes_ file for the new
local _drops_, the `-B` parameter is required to name a bootsrap node for the first run.
Once the network is settled, every peer may shutdown and restart their _drops_ instances
via `dropsd -T 87cb0b3623b7cdcc696e8f172b06820a`, as the _nodes_ file should already be properly
populated at this point.



