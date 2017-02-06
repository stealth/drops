/*
 * This file is part of the drops crypto messenger.
 *
 * (C) 2016-2017 by Sebastian Krahmer,
 *                  sebastian [dot] krahmer [at] gmail [dot] com
 *
 * drops is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * drops is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with drops.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/cdefs.h>
#define _POSIX_SOURCE
#include <stdint.h>
#include <string>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <memory>
#include <utility>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <ctype.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "peer.h"
#include "drops.h"
#include "deleters.h"
#include "flavor.h"
#include "ssl.h"
#include "misc.h"
#include "numbers.h"
#include "config.h"


extern "C" {
#include <openssl/ssl.h>
#include <openssl/evp.h>
}


using namespace std;

namespace drops {


int log::init(const string &path)
{
	if (!(f = fopen(path.c_str(), "a")))
		return -1;

	return 0;
}


int log::logit(const string &tag, const string &s, time_t t)
{
	if (!f)
		return -1;

	if (!t)
		t = time(nullptr);
	struct tm tm;
	memset(&tm, 0, sizeof(tm));

	localtime_r(&t, &tm);
	char local_date[64] = {0};
	strftime(local_date, sizeof(local_date) - 1, "%a, %d %b %Y %H:%M:%S", &tm);

	string msg = s;
	string::size_type nl = 0;
	if (msg.size() > 1 && (nl = msg.find_last_of("\n")) == msg.size() - 1)
		msg.erase(nl, 1);
	for (string::size_type i = 0; i < msg.size(); ++i) {
		if (!isprint(msg[i]))
			msg[i] = '?';
	}

	fprintf(f, "%s: %s%s\n", local_date, tag.c_str(), msg.c_str());
	fflush(f);
	return 0;
}



int drops_engine::init(const string &laddr, const string &lport, const string &laddr6, const string &lport6, const string &id, const string &tag)
{
	d_id = id;
	d_tag = tag;
	if (d_tag != "global" && !is_hex_hash(d_tag))
		return build_error("init: Invalid tag", -1);
	if (d_tag != "global")
		max_msg_size = 10*1024*1024;

	d_log.init(d_base + "/" + d_tag + "/log.txt");

	if ((sslc = new (nothrow) ssl_container) == nullptr)
		return build_error("init::new: OOM", -1);
	if (sslc->init(d_base + "/" + d_tag + "/" + d_capath,
	               d_base + "/" + d_tag + "/" + d_cpath,
	               d_base + "/" + d_tag + "/" + d_kpath) < 0)
		return build_error("init::" + string(sslc->why()), -1);

	// setup message store and cache
	d_store = new (nothrow) drops_store(d_base, d_tag);
	if (!d_store)
		return build_error("init::new: OOM", -1);
	if (d_store->init() < 0)
		return build_error("init::storage init:" + string(d_store->why()), -1);
	if (d_store->build_index() < 0)
		return build_error("init::storage init:" + string(d_store->why()), -1);

	nodes_from_store();


	// allocate poll array
	struct rlimit rl;
	rl.rlim_cur = (1<<16);
	rl.rlim_max = (1<<16);

	// as user we cant set it higher
	if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
		errno = 0;
		if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
			return build_error("init::getrlimit:", -1);
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) < 0)
			return build_error("init::getrlimit:", -1);
	}

	if ((d_pfds = new (nothrow) pollfd[rl.rlim_cur]) == nullptr)
		return build_error("init::new: OOM", -1);
	memset(d_pfds, 0, sizeof(struct pollfd) * rl.rlim_cur);
	for (unsigned int i = 0; i < rl.rlim_cur; ++i)
		d_pfds[i].fd = -1;

	if ((d_peers = new (nothrow) drops_peer*[rl.rlim_cur]) == nullptr)
		return build_error("init::new: OOM", -1);
	memset(d_peers, 0, rl.rlim_cur*sizeof(drops_peer *));

	int r = 0, flags = 0, sock_fd = -1, one = 1;
	addrinfo hint;

	if (laddr.size() > 0) {
		memset(&hint, 0, sizeof(hint));
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_family = AF_INET;

		if ((r = getaddrinfo(laddr.c_str(), lport.c_str(), &hint, &d_baddr)) != 0)
			return build_error("init::getaddrinfo:" + string(gai_strerror(r)), -1);

		if (d_baddr->ai_family != AF_INET)
			return build_error("init: laddr config option is not a valid IPv4 address.", -1);

		if ((sock_fd = socket(d_baddr->ai_family, SOCK_STREAM, 0)) < 0)
			return build_error("init::socket:", -1);

		flags = fcntl(sock_fd, F_GETFL);
		fcntl(sock_fd, F_SETFL, flags|O_NONBLOCK);

		setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
		one = 1;
		setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

		if (bind(sock_fd, d_baddr->ai_addr, d_baddr->ai_addrlen) < 0)
			return build_error("init::bind:", -1);

		if (listen(sock_fd, SOMAXCONN) < 0)
			return build_error("init::listen:", -1);

		// setup listening socket for polling
		d_max_fd = sock_fd;
		d_first_fd = sock_fd;
		d_pfds[sock_fd].fd = sock_fd;
		d_pfds[sock_fd].events = POLLIN|POLLOUT;

		d_peers[sock_fd] = new (nothrow) drops_peer(laddr, lport, sock_fd, d_baddr->ai_family);
		if (!d_peers[sock_fd])
			return build_error("init::new: OOM", -1);
		d_peers[sock_fd]->state(STATE_ACCEPTING);
	}

	if (laddr6.size() == 0) {
		if (laddr.size() == 0)
			return build_error("init: Neither IPv4 nor IPv6 adddress given to bind to!", -1);
		return 0;
	}

	// Now the same for the IPv6 bind address
	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_family = AF_INET6;

	if ((r = getaddrinfo(laddr6.c_str(), lport6.c_str(), &hint, &d_baddr6)) != 0)
		return build_error("init::getaddrinfo:" + string(gai_strerror(r)), -1);

	if (d_baddr6->ai_family != AF_INET6)
		return build_error("init: laddr6 config option is not a valid IPv6 address.", -1);

	if ((sock_fd = socket(d_baddr6->ai_family, SOCK_STREAM, 0)) < 0)
		return build_error("init::socket:", -1);

	one = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
	one = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	if (bind(sock_fd, d_baddr6->ai_addr, d_baddr6->ai_addrlen) < 0)
		return build_error("init::bind:", -1);

	if (listen(sock_fd, SOMAXCONN) < 0)
		return build_error("init::listen:", -1);

	flags = fcntl(sock_fd, F_GETFL);
	fcntl(sock_fd, F_SETFL, flags|O_NONBLOCK);

	// setup listening socket for polling
	if (sock_fd > d_max_fd)
		d_max_fd = sock_fd;
	if (d_first_fd < 0)
		d_first_fd = sock_fd;

	d_pfds[sock_fd].fd = sock_fd;
	d_pfds[sock_fd].events = POLLIN|POLLOUT;

	d_peers[sock_fd] = new (nothrow) drops_peer(laddr6, lport6, sock_fd, d_baddr6->ai_family);
	if (!d_peers[sock_fd])
		return build_error("init::new: OOM", -1);
	d_peers[sock_fd]->state(STATE_ACCEPTING);

	return 0;
}


void drops_engine::calc_max_fd()
{
	// find the highest fd that is in use
	for (int i = d_max_fd; i >= d_first_fd; --i) {
		if (d_peers[i] && d_peers[i]->state() != STATE_NONE) {
			d_max_fd = i;
			return;
		}
		if (d_pfds[i].fd != -1) {
			d_max_fd = i;
			return;
		}
	}
}


drops_peer *drops_engine::connect(const string &node)
{
	if (node.find("[") != 0)
		return build_error("connect: Invalid node format.", nullptr);

	string::size_type pidx = node.find("]:");
	if (pidx == string::npos)
		return build_error("connect: Invalid node format.", nullptr);

	string ip = node.substr(1, pidx - 1);
	string port = node.substr(pidx + 2);

	return connect(ip, port);
}


drops_peer *drops_engine::connect(const string &ip, uint16_t port)
{
	char sport[32] = {0};
	snprintf(sport, sizeof(sport) - 1, "%hu", port);
	return connect(ip, sport);
}


drops_peer *drops_engine::connect(const string &ip, const string &port)
{
	int r = 0, sock_fd = -1;
	addrinfo hint, *tai = nullptr;
	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = SOCK_STREAM;

	if ((r = getaddrinfo(ip.c_str(), port.c_str(), &hint, &tai)) < 0)
		return build_error("getaddrinfo:" + string(gai_strerror(r)), nullptr);

	unique_ptr<addrinfo, addrinfo_del> ai(tai, freeaddrinfo);

	if (ai->ai_family == AF_INET && !d_baddr)
		return build_error("socket: Not bound to IPv4 socket but IPv4 node requested.", nullptr);
	if (ai->ai_family == AF_INET6 && !d_baddr6)
		return build_error("socket: Not bound to IPv6 socket but IPv6 node requested.", nullptr);

	if ((sock_fd = socket(ai->ai_family, SOCK_STREAM, 0)) < 0)
		return build_error("socket:", nullptr);

	int flags = fcntl(sock_fd, F_GETFL);
	fcntl(sock_fd, F_SETFL, flags|O_NONBLOCK);

	int one = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
	one = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	// Bind to the right local address (v4 vs. v6) depending on peer node is v4 or v6
	if (ai->ai_family == AF_INET) {
		if (bind(sock_fd, d_baddr->ai_addr, d_baddr->ai_addrlen) < 0)
			return build_error("bind:", nullptr);
	} else if (ai->ai_family == AF_INET6) {
		if (bind(sock_fd, d_baddr6->ai_addr, d_baddr6->ai_addrlen) < 0)
			return build_error("bind:", nullptr);
	} else
		return build_error("bind: Unknown address family.", nullptr);

	if (::connect(sock_fd, ai->ai_addr, ai->ai_addrlen) < 0 && errno != EINPROGRESS) {
		close(sock_fd);
		return build_error("connect:", nullptr);
	}


	uint16_t portnum = (uint16_t)strtoul(port.c_str(), nullptr, 10);
	drops_peer *p = new (nothrow) drops_peer(ip, portnum, sock_fd, ai->ai_family);
	if (!p)
		return build_error("connect::new: OOM", nullptr);
	p->state(STATE_CONNECTING);
	p->timer(d_now);
	p->d_store_idx = d_store->begin();
	++d_npeers;

	if (sock_fd > d_max_fd)
		d_max_fd = sock_fd;

	d_pfds[sock_fd].fd = sock_fd;
	d_pfds[sock_fd].events = POLLIN|POLLOUT;
	d_pfds[sock_fd].revents = 0;

	return p;
}


int drops_engine::loop()
{
	int r = 0;
	drops_peer *tmp_p = nullptr;
	string s = "", id = "", me = "";
	time_t last_outq_check = 0, last_nodes_store = 0;
	pair<time_t, time_t> tp;

	for (;;) {
		if ((r = poll(d_pfds, d_max_fd + 1, 2000)) < 0)
			continue;

		d_now = time(nullptr);
		d_store->update_time(d_now);

		for (int i = d_first_fd; i <= d_max_fd; ++i) {
			ostringstream msg;

			if (!d_peers[i] || d_pfds[i].fd == -1)
				continue;

			if (d_pfds[i].revents == 0 && d_peers[i]->state() != STATE_PINGPONG_SLEEP) {
				if (d_peers[i]->state() == STATE_ACCEPTING)
					continue;
				else if (d_peers[i]->state() == STATE_CONNECTING && d_now - d_peers[i]->timer() > timeouts::connect) {
					cleanup(i, timeouts::reconnect);
					continue;
				} else if (d_now - d_peers[i]->timer() > timeouts::pingpong) {
					d_log.logit(">", "pingpong timeout for " + d_peers[i]->node(), d_now);
					cleanup(i, timeouts::reconnect);
					continue;
				} else if (d_peers[i]->state() == STATE_FAIL) {
					cleanup(i, timeouts::reconnect);
					continue;
				}

				// revents is 0 and state is not sleeping, so skip handling this peer
				// any further
				continue;
			}


			if (d_peers[i]->state() != STATE_ACCEPTING) {
				if ((d_pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) != 0) {
					cleanup(i, timeouts::reconnect);
					continue;
				}
			}

			d_pfds[i].revents = 0;

			switch (d_peers[i]->state()) {
			case STATE_NONE:
				continue;
			case STATE_ACCEPTING:
				if (!(tmp_p = d_peers[i]->accept(me)))
					break;

				d_myaddrs[me] = d_now;

				// Remember any potentially pending reconnect timers
				if (d_learned_nodes.count(tmp_p->node()) > 0) {
					tp = d_learned_nodes[tmp_p->node()];
					d_learned_nodes.erase(tmp_p->node());
				} else
					tp = make_pair(timeouts::initial, d_now);

				d_connected_nodes[tmp_p->node()] = tp;

				if (tmp_p->fd() > d_max_fd)
					d_max_fd = tmp_p->fd();

				tmp_p->state(STATE_ACCEPT_DONE);
				tmp_p->timer(d_now);
				tmp_p->d_store_idx = d_store->begin();
				d_peers[tmp_p->fd()] = tmp_p;
				d_pfds[tmp_p->fd()].fd = tmp_p->fd();
				d_pfds[tmp_p->fd()].events = POLLIN;		// expect a TLS client hello
				d_pfds[tmp_p->fd()].revents = 0;
				break;
			case STATE_ACCEPT_DONE:
				if ((r = d_peers[i]->ssl_accept(sslc->sctx())) == 1) {
					d_peers[i]->timer(d_now);
					d_pfds[i].events = POLLIN;		// expect a handshake snd from client peer
					d_peers[i]->state(STATE_HANDSHAKE_RCV);
				} else if (r < 0) {
					d_log.logit("<", "Error for " + d_peers[i]->node() + " " + d_peers[i]->why(), d_now);
					cleanup(i);
				} else
					d_pfds[i].events = POLLIN|POLLOUT;	// SSL_accept() ongoing and may r/w

				break;
			case STATE_CONNECTING:
				if (d_peers[i]->finish_connect() < 0) {
					cleanup(i, timeouts::reconnect);
					break;
				}
				d_peers[i]->state(STATE_CONNECT_DONE);
				d_peers[i]->timer(d_now);
				d_pfds[i].events = POLLOUT;			// we will be sending a TLS client hello next
				break;
			case STATE_CONNECT_DONE:
				if ((r = d_peers[i]->ssl_connect(sslc->cctx())) == 1) {
					d_peers[i]->timer(d_now);
					d_pfds[i].events = POLLOUT;		// we will be sending a client handshake msg
					d_peers[i]->state(STATE_SSL_CONNECT_DONE);
				} else if (r < 0) {
					d_log.logit(">", "Error for " + d_peers[i]->node() + " " + d_peers[i]->why(), d_now);
					cleanup(i);	// dont tolerate SSL_connect() errors for reconnects
				} else
					d_pfds[i].events = POLLIN|POLLOUT;	// SSL_connect() ongoing and may r/w

				break;
			case STATE_SSL_CONNECT_DONE:
				msg<<"{drops;version="<<d_version<<",type=hello,tag="<<d_tag<<",peerid="<<d_id;
				append_cnodes(msg);
				msg<<",end}\n";
				d_peers[i]->set_smsg(msg.str());
				d_peers[i]->state(STATE_HANDSHAKE_SND);
				d_peers[i]->timer(d_now);
				// FALLTHROUGH
			case STATE_HANDSHAKE_SND:
				if ((r = d_peers[i]->write1(d_pfds[i].events)) < 0) {
					d_log.logit(">", "Write error to " + d_peers[i]->node() + " " + d_peers[i]->why(), d_now);
					cleanup(i, timeouts::reconnect);
					break;
				}
				if (r > 0)
					d_peers[i]->timer(d_now);

				if (d_peers[i]->is_write_done()) {
					// If we are the "passive" peer, that got the connect from remote,
					// we already went through RCV state
					if (d_peers[i]->has_accepted())
						d_peers[i]->state(STATE_PINGPONG_RCV);
					else
						d_peers[i]->state(STATE_HANDSHAKE_RCV);

					d_pfds[i].events = POLLIN;		// we expect a client message next -- either way
				}

				break;
			case STATE_HANDSHAKE_RCV:
				if ((r = d_peers[i]->read1(d_pfds[i].events)) < 0) {
					d_log.logit("<", "Read error from " + d_peers[i]->node() + " " + d_peers[i]->why(), d_now);
					cleanup(i, timeouts::reconnect);
					break;
				}
				if (r > 0)
					d_peers[i]->timer(d_now);

				if (d_peers[i]->is_read_done()) {
					if (parse_handshake(d_peers[i], d_peers[i]->get_rmsg(s)) < 0) {
						d_log.logit("<", "Handshake error from " + d_peers[i]->node() + " " + d_err, d_now);
						cleanup(i, timeouts::reconnect);
						break;
					}

					// If we are the "passive" peer, that got the connect from remote,
					// we also need to go to SND state
					if (d_peers[i]->has_accepted()) {
						msg<<"{drops;version="<<d_version<<",type=hello,tag="<<d_tag<<",peerid="<<d_id;
						append_cnodes(msg);
						msg<<",end}\n";
						d_peers[i]->set_smsg(msg.str());
						d_peers[i]->state(STATE_HANDSHAKE_SND);
					} else {
						next_pingpong_msg(d_peers[i], msg);
						d_peers[i]->set_smsg(msg.str());
						d_peers[i]->state(STATE_PINGPONG_SND);
					}

					// 0 means its valid handshaked, set reconnect timer to 0
					d_connected_nodes[d_peers[i]->node()].first = timeouts::none;
					d_has_new_nodes = 1;
					d_log.logit("<", d_peers[i]->node() + (d_peers[i]->has_accepted() ? " via accept() " : " via connect() ") + s, d_now);

					d_pfds[i].events = POLLOUT;		// we will be sending a msg next
				}

				break;
			case STATE_PINGPONG_SND:
				if ((r = d_peers[i]->write1(d_pfds[i].events)) < 0) {
					d_log.logit(">", "Write error to " + d_peers[i]->node() + " " + d_peers[i]->why(), d_now);
					cleanup(i, timeouts::reconnect);
					break;
				}
				if (r > 0)
					d_peers[i]->timer(d_now);

				if (d_peers[i]->is_write_done()) {
					d_peers[i]->state(STATE_PINGPONG_RCV);
					d_pfds[i].events = POLLIN;
				}

				break;
			case STATE_PINGPONG_RCV:
				if ((r = d_peers[i]->read1(d_pfds[i].events)) < 0) {
					d_log.logit("<", "Read error from " + d_peers[i]->node() + " " + d_peers[i]->why(), d_now);
					cleanup(i, timeouts::reconnect);
					break;
				}
				if (r > 0)
					d_peers[i]->timer(d_now);

				if (d_peers[i]->is_read_done()) {
					if (parse_pingpong_msg(d_peers[i], d_peers[i]->get_rmsg(s)) < 0) {
						d_log.logit("<", "Pingpong error from " + d_peers[i]->node() + " " + d_err, d_now);
						cleanup(i);	// no reconnect for failed parse
						break;
					}
					if (d_peers[i]->has_accepted() &&
					    d_peers[i]->last_have() == "nothing" && d_peers[i]->last_offer() == "nothing") {
						d_peers[i]->state(STATE_PINGPONG_SLEEP);
						d_pfds[i].events = 0;
					} else {
						next_pingpong_msg(d_peers[i], msg);
						d_peers[i]->set_smsg(msg.str());
						d_peers[i]->state(STATE_PINGPONG_SND);
						d_pfds[i].events = POLLOUT;
					}
				}

				break;
			case STATE_PINGPONG_SLEEP:
				// sleep for TIMEOUT_SLEEPING seconds
				if (d_now - d_peers[i]->timer() < timeouts::sleeping && d_has_new_msg == 0)
					break;

				next_pingpong_msg(d_peers[i], msg);
				d_peers[i]->set_smsg(msg.str());
				d_peers[i]->state(STATE_PINGPONG_SND);
				d_peers[i]->timer(d_now);
				d_pfds[i].events = POLLOUT;
				break;
			case STATE_FAIL:
				cleanup(i, timeouts::reconnect);
				break;
			}
		}

		calc_max_fd();

		// to make sure its going to the whole list of peers at least once, to wake up
		// potentially sleeping peers, its set to 2 if there is a new message
		if (d_has_new_msg > 0)
			--d_has_new_msg;

		if (numbers->nkeys() > 0 && d_now - last_outq_check > 3) {
			string inmsg = "", fname = "";
			d_store->load_outq(inmsg, fname);

			if (inmsg.size() > 0) {

				// We need to fetch a submit-key that matches bitsize
				// for the actual date of signing (the cloaked date)
				time_t cdate = cloak_date(d_now);
				Numbers::submit_key *sk = numbers->get1(cdate);

				// Might be we failed for finding submit keys, if a "new day"
				// broke since RSA generator generated their keys. In this case, try
				// in next loop iteration and leave message file in place.
				if (sk) {
					if (sign_message(inmsg, sk, cdate) == 0) {
						d_store->store(sk->id, inmsg, cdate);
						d_has_new_msg = 2;
						unlink(fname.c_str());
					}
				}
				delete sk;
			}

			last_outq_check = d_now;
		}

		// connect() is increasing d_npeers
		for (auto n = d_learned_nodes.begin(); n != d_learned_nodes.end() && d_npeers < d_min_peers;) {

			// honor re-connect timeout to not bomb peers
			if (n->second.second > d_now) {
				++n;
				continue;
			}

			string node = n->first;

			// transfer re-connect timers from learned_nodes to connected_nodes
			tp = n->second;
			n = d_learned_nodes.erase(n);

			// dont connect twice
			if (d_connected_nodes.count(node) > 0 || d_myaddrs.count(node) > 0)
				continue;

			drops_peer *p = connect(node);
			if (!p) {
				d_log.logit(">", "drops_engine::loop:" + d_err, d_now);
			} else {
				d_connected_nodes[node] = tp;
				d_peers[p->fd()] = p;
			}
		}

		if (d_has_new_nodes && d_now - last_nodes_store > 30) {
			nodes_to_store();
			d_has_new_nodes = 0;
			last_nodes_store = d_now;
		}

		d_store->maybe_cache_clear();

	}

	return 0;
}


static int normalize_node(string &node)
{
	string s = node;
	node = "";

	string::size_type i = 0, bracket = 0;

	if ((i = s.find("[")) != 0)
		return -1;
	if ((bracket = s.find("]:")) == string::npos)
		return -1;
	if (bracket + 2 >= s.size())
		return -1;

	string ip = s.substr(1, bracket - 1);

	char buf[256] = {0};
	in_addr in = {0};
	if (inet_pton(AF_INET, ip.c_str(), &in) != 1) {
		in6_addr in6 = {0};
		if (inet_pton(AF_INET6, ip.c_str(), &in6) != 1)
			return -1;
		else
			inet_ntop(AF_INET6, &in6, buf, sizeof(buf) - 1);
	} else {
		inet_ntop(AF_INET, &in, buf, sizeof(buf) - 1);
	}

	uint16_t port = 0;
	if (sscanf(s.c_str() + bracket + 2, "%hu", &port) != 1 || port < 1024)
		return -1;

	char pbuf[32] = {0};
	snprintf(pbuf, sizeof(pbuf) - 1, "%hu", port);

	node = "[" + string(buf) + "]:" + pbuf;
	return 0;
}


int drops_engine::parse_handshake(drops_peer *p, const string &hsk)
{
	string::size_type idx = string::npos, comma = 0, i = 0, bracket = 0;

	if ((idx = hsk.find("{drops;version=")) != 0)
		return build_error("parse_handshake: Not a drops message", -1);
	i = 15;

	unsigned int v = 0;
	if (sscanf(hsk.c_str() + i, "%u,", &v) != 1)
		return -1;
	if (d_version < v)
		d_log.logit("<", "New drops version detected? pull the git and upgrade", d_now);

	if (hsk.find(",type=hello,", i) == string::npos)
		return build_error("parse_handshake: missing hello", -1);
	if ((idx = hsk.find(",tag=", i)) == string::npos)
		return build_error("parse_handshake: missing tag", -1);
	idx += 5;
	if ((comma = hsk.find(",", idx)) == string::npos)
		return build_error("parse_handshake: missing comma", -1);
	string rtag = hsk.substr(idx, comma - idx);
	if (rtag != "global" && !is_hex_hash(rtag))
		return build_error("parse_handshake: invalid tag", -1);
	if (rtag != d_tag)
		return build_error("parse_handshake: tag mismatch", -1);
	// check if we are trying to connect to ourself or already connected nodes, by comparing peer id
	if ((idx = hsk.find(",peerid=", i)) == string::npos)
		return build_error("parse_handshake: missing peerid", -1);
	idx += 8;
	if ((comma = hsk.find(",", idx)) == string::npos)
		return build_error("parse_handshake: missing comma", -1);
	string peerid = hsk.substr(idx, comma - idx);

	if (peerid == d_id || d_peer_ids.count(peerid) > 0)
		return build_error("parse_handshake: already connected to that peer", -1);

	p->id(peerid);
	d_peer_ids[peerid] = 1;

	// learn new nodes
	string node = "";

	for (int found_nodes = 0; found_nodes < 100; ++found_nodes) {
		if ((i = hsk.find("node=[", i)) == string::npos)
			break;
		i += 5;
		if ((comma = hsk.find(",", i)) == string::npos)
			return -1;
		node = hsk.substr(i, comma - i);

		if (normalize_node(node) < 0)
			return -1;

		i = comma;

		// silently ignore
		if (d_myaddrs.count(node) > 0) {
			d_log.logit("<", "Silently ignoring node " + node + " from " + p->node(), d_now);
			continue;
		}

		if (d_connected_nodes.count(node) == 0 && d_learned_nodes.count(node) == 0)
			d_learned_nodes[node] = make_pair(timeouts::initial, d_now + timeouts::initial);// 1s reconnect timer when learned

		d_has_new_nodes = 1;
	}

	return 0;
}



int drops_engine::parse_pingpong_msg(drops_peer *p, const string &pp)
{
	if (!p)
		return -1;

	string::size_type idx = string::npos, comma = 0, i = 0, nl = 0;

	if ((nl = pp.find(",\n")) == string::npos)
		return -1;

	// unsigned modifiable first line
	string pp1 = pp.substr(0, nl + 2);

	if ((idx = pp1.find("{drops;version=")) != 0)
		return build_error("parse_pingpong_msg: Not a drops message.", -1);
	i = 15;

	unsigned int v = 0;
	if (sscanf(pp1.c_str() + i, "%u,", &v) != 1)
		return build_error("parse_pingpong_msg: Mssing version.", -1);
	if (d_version < v)
		d_log.logit("<", "New drops version detected? pull the git and upgrade\n", d_now);

	if (pp1.find(",type=pp,", i) == string::npos)
		return build_error("parse_pingpong_msg: Missing type.", -1);

	if ((idx = pp1.find(",have=", i)) == string::npos)
		return build_error("parse_pingpong_msg: Missing have=.", -1);
	idx += 6;
	if ((comma = pp1.find(",", idx)) == string::npos)
		return build_error("parse_pingpong_msg: Missing comma.", -1);
	string have = pp1.substr(idx, comma - idx);
	if (!is_valid_have(have))
		return build_error("parse_pingpong_msg: Invalid have=", -1);

	if (pp1.find(",want=yes,", i) != string::npos)
		p->wants_last_offer(1);
	else if (pp1.find(",want=no,", i) != string::npos)
		p->wants_last_offer(0);
	else
		return build_error("parse_pingpong_msg: missing or wrong want=", -1);

	const string &body = pp.substr(nl + 2);

	// signature first, if any. (Body is optional due to "nothing")
	if ((idx = body.find("rsasig=")) != 0) {
		// As we return early, also set last_have()
		p->last_have(have);
		return 0;
	}
	idx += 7;
	if ((comma = body.find(",", idx)) == string::npos)
		return build_error("parse_pingpong_msg: Missing comma.", -1);
	string b64rsasig = body.substr(idx, comma - idx);

	if ((idx = body.find(",msgid=")) == string::npos)
		return build_error("parse_pingpong_msg: Missing msgid=", -1);
	idx += 7;
	if ((comma = body.find(",", idx)) == string::npos)
		return build_error("parse_pingpong_msg: Missing comma.", -1);

	string msgid = body.substr(idx, comma - idx);
	if (!is_hex_hash(msgid) || (msgid != p->last_have() && p->last_have() != "nothing"))
		return build_error("parse_pingpong_msg: Wrong msgid format.", -1);

	p->last_have(have);

	if ((idx = body.find(",rsakey=")) == string::npos)
		return build_error("parse_pingpong_msg: Missing rsakey=", -1);
	idx += 8;
	if ((comma = body.find(",", idx)) == string::npos)
		return build_error("parse_pingpong_msg: Missing comma.", -1);
	string pem_rsakey = body.substr(idx, comma - idx);


	if ((idx = body.find(",date=")) == string::npos)
		return build_error("parse_pingpong_msg: Missing date=", -1);
	idx += 6;
	if ((comma = body.find(",", idx)) == string::npos)
		return build_error("parse_pingpong_msg: Missing comma.", -1);
	time_t date = (time_t)strtoull(body.substr(idx, comma - idx).c_str(), nullptr, 10);

	EVP_PKEY *pk = check_numbers(pem_rsakey, msgid, date, d_now);
	if (!pk) {
		d_log.logit("<", "Submit-key failed to verify for msgid " + msgid + " from " + p->node(), d_now);
		if (p->fails(1) >= p->max_fails())
			return build_error("parse_pingpong_msg: Max fails reached.", -1);

		return 0;
	}

	int is_good = verify_message(body, pk, b64rsasig);
	EVP_PKEY_free(pk);

	if (is_good != 1) {
		d_log.logit("<", "Failed signature on msgid " + msgid + " from " + p->node(), d_now);
		if (p->fails(1) >= p->max_fails())
			return build_error("parse_pingpong_msg: Max fails reached.", -1);

		return 0;
	}

	d_store->store(msgid, body, date);

	if (config::filter.filter(body))
		d_store->store_inq(msgid, body);

	d_has_new_msg = 22;

	return 0;
}


ostringstream &drops_engine::next_pingpong_msg(drops_peer *p, ostringstream &msg)
{
	msg<<"{drops;version="<<d_version<<",type=pp,tag="<<d_tag<<",peerid="<<d_id;

	string have = "", body = "";
	p->d_store_idx = d_store->fetch_inc(p->d_store_idx, have);

	string want = ",want=";
	if (p->last_have() == "nothing" || d_store->has_id(p->last_have()))
		want += "no";
	else
		want += "yes";
	msg<<",have="<<have<<want<<",\n";		// after first newline, rest is signed
	if (p->last_offer() != "nothing" && p->wants_last_offer()) {
		if (d_store->load(p->last_offer(), body) == 1)
			msg<<body;
		else {
			msg<<",end}\n";
		}
	} else {
		msg<<",end}\n";
	}

	p->last_offer(have);

	return msg;
}



// append all connected nodes to ostream
ostringstream &drops_engine::append_cnodes(ostringstream &msg)
{

	msg<<",startnodes";
	for (auto i = d_connected_nodes.begin(); i != d_connected_nodes.end(); ++i) {
		// 0 reconnect timer means its valid handshaked
		if (i->second.first == timeouts::none)
			msg<<",node="<<i->first;
	}
	msg<<",endnodes";
	return msg;
}


int drops_engine::nodes_to_store()
{
	string path = d_base + "/" + d_tag + "/nodes",
	       tpath = path + ".tmp";

	unique_ptr<FILE, FILE_del> f(fopen(tpath.c_str(), "w"), fclose);
	if (!f.get())
		return build_error("nodes_to_store::fopen:", -1);

	fprintf(f.get(), "# Automatically generated. Do not edit.\n");

	for (auto i : d_connected_nodes)
		fprintf(f.get(), "%s,%016llu,\n", i.first.c_str(), (unsigned long long)i.second.first);
	for (auto i : d_learned_nodes)
		fprintf(f.get(), "%s,%016llu,\n", i.first.c_str(), (unsigned long long)i.second.first);

	f.reset();

	unlink(path.c_str());
	rename(tpath.c_str(), path.c_str());
	return 0;
}


int drops_engine::nodes_from_store()
{
	string path = d_base + "/" + d_tag + "/nodes";

	unique_ptr<FILE, FILE_del> f(fopen(path.c_str(), "r"), fclose);

	if (!f.get()) {
		string tpath = path + ".tmp";
		struct stat st;
		if (stat(tpath.c_str(), &st) == 0)
			rename(tpath.c_str(), path.c_str());
		f.reset(fopen(path.c_str(), "r"));
		if (!f.get())
			return build_error("nodes_from_store::fopen:", -1);
	}

	unsigned long long t = 0;
	uint16_t sport = 0;
	char buf[1024 + 1] = {0};
	string::size_type pidx = 0, comma = 0;
	do {
		memset(buf, 0, sizeof(buf));
		if (!fgets(buf, sizeof(buf) - 1, f.get()))
			break;
		if (buf[0] == '#')
			continue;
		string line = buf;

		if (line.find("[") != 0)
			continue;
		if ((pidx = line.find("]:")) == string::npos)
			continue;
		if ((comma = line.find(",")) == string::npos)
			continue;
		string ip = line.substr(1, pidx - 1);

		if (inet_pton(AF_INET, ip.c_str(), buf) != 1) {
			if (inet_pton(AF_INET6, ip.c_str(), buf) != 1)
				continue;
		}

		// ignore time-punish for now
		if (sscanf(line.c_str() + pidx + 2, "%hu,%016llu,", &sport, &t) != 2 || sport < 1024)
			continue;

		d_learned_nodes[line.substr(0, comma)] = make_pair(timeouts::initial, d_now);

	} while (!feof(f.get()));

	f.reset();
	return 0;
}


int drops_engine::cleanup(int i, time_t howlong)
{
	if (i < 0)
		return -1;

	d_pfds[i].fd = -1;
	d_pfds[i].events = d_pfds[i].revents = 0;

	if (!d_peers)
		return -1;

	string n = d_peers[i]->node();

	// cleanup() can only happen on nodes that are in d_connected_nodes
	time_t t = d_connected_nodes[n].first;
	d_connected_nodes.erase(n);

	// accumulate reconnect timers so we get rid of dead nodes
	// automatically
	if (howlong > 0) {
		t += howlong;
		d_learned_nodes[n] = make_pair(t, d_now + t);
	} else
		d_learned_nodes.erase(n);

	d_peer_ids.erase(d_peers[i]->id());

	delete d_peers[i];
	d_peers[i] = nullptr;

	if (i == d_max_fd && d_max_fd > d_first_fd)
		--d_max_fd;

	--d_npeers;

	return 0;
}


}

