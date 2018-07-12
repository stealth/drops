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

#include <stdint.h>
#include <string>
#include <memory>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "misc.h"
#include "peer.h"
#include "config.h"
#include "deleters.h"
#include "flavor.h"

extern "C" {
#include <openssl/ssl.h>
}


using namespace std;

namespace drops {


int drops_peer::read1(short &events)
{
	char buf[4096] = {0};

	if (d_rmsg.size() > max_msg_size) {
		events = 0;
		d_state = STATE_FAIL;
		return build_error("read1: msg size too large.", -1);
	}

	events = POLLIN;

	int r = SSL_read(d_ssl, buf, sizeof(buf) - 1);
	d_ssl_e = ERR_peek_error();
	switch (SSL_get_error(d_ssl, r)) {
	case SSL_ERROR_NONE:
		d_rmsg += string(buf, r);
		return r;
	// not ready yet? try later
	case SSL_ERROR_WANT_WRITE:
		events |= POLLOUT;
		// FALLTHROUGH
	case SSL_ERROR_WANT_READ:
		return 0;
	}

	events = 0;
	d_state = STATE_FAIL;
	return build_error("read1::SSL_read:", -1);
}


int drops_peer::write1(short &events)
{
	if (d_smsg.size() == 0)
		return 0;

	events = POLLOUT;

	string s = d_smsg.substr(0, 1024);

	int r = SSL_write(d_ssl, s.c_str(), s.size());
	d_ssl_e = ERR_peek_error();
	switch (SSL_get_error(d_ssl, r)) {
	case SSL_ERROR_NONE:
		d_smsg.erase(0, r);
		return r;
	// not ready yet? try later
	case SSL_ERROR_WANT_READ:
		events |= POLLIN;
		// FALLTHROUGH
	case SSL_ERROR_WANT_WRITE:
		return 0;
	}

	events = 0;
	d_state = STATE_FAIL;
	return build_error("write1::SSL_write:", -1);
}



int drops_peer::finish_connect()
{
	if (d_state != STATE_CONNECTING) {
		d_state = STATE_FAIL;
		return build_error("finish_connect: wrong state?!", -1);
	}

	int e = 0;
	socklen_t elen = sizeof(e);
	if (getsockopt(d_fd, SOL_SOCKET, SO_ERROR, &e, &elen) < 0) {
		d_state = STATE_FAIL;
		return build_error("finish_connect::getsockopt:", -1);
	}
	if (e != 0) {
		d_state = STATE_FAIL; errno = e;
		return build_error("finish_connect:", -1);
	}

	return 0;
}


// actually a factory for new drops_peers
drops_peer *drops_peer::accept(string &laddr)
{
	laddr = "";

	struct sockaddr_in sin = {0};
	struct sockaddr_in6 sin6 = {0};
	struct sockaddr *saddr = (sockaddr *)&sin;
	socklen_t slen = sizeof(sin);

	if (d_af == AF_INET6) {
		saddr = (struct sockaddr *)&sin6;
		slen = sizeof(sin6);
	}

	int afd = flavor::accept(d_fd, saddr, &slen, flavor::NONBLOCK);
	if (afd < 0) {
		if (errno == EMFILE || errno == ENFILE) {
		}
		return build_error("accept::accept:", nullptr);
	}

	char remote[256] = {0};
	uint16_t rport = 0;
	if (d_af == AF_INET) {
		inet_ntop(AF_INET, &sin.sin_addr, remote, sizeof(remote) - 1);
		rport = ntohs(sin.sin_port);
		slen = sizeof(sin);	// 2nd run for getsockname()
	} else {
		inet_ntop(AF_INET6, &sin6.sin6_addr, remote, sizeof(remote) - 1);
		rport = ntohs(sin6.sin6_port);
		slen = sizeof(sin6);
	}


	// get our own endpoint address+port
	if (getsockname(afd, saddr, &slen) < 0)
		return build_error("accept::getsockname:", nullptr);

	char local[256] = {0}, lport[32] = {0};
	if (d_af == AF_INET) {
		inet_ntop(AF_INET, &sin.sin_addr, local, sizeof(local) - 1);
		snprintf(lport, sizeof(lport) - 1, "%hu", ntohs(sin.sin_port));
	} else {
		inet_ntop(AF_INET6, &sin6.sin6_addr, local, sizeof(local) - 1);
		snprintf(lport, sizeof(lport) - 1, "%hu", ntohs(sin6.sin6_port));
	}

	laddr = "[" + string(local) + "]:" + lport;

	return new (nothrow) drops_peer(remote, rport, afd, d_af);
}


int drops_peer::ssl_connect(SSL_CTX *ssl_ctx)
{
	int r = 0;

	if (!d_ssl) {
		if ((d_ssl = SSL_new(ssl_ctx)) == nullptr) {
			d_state = STATE_FAIL;
			return build_error("ssl_connect::SSL_new:", -1);
		}
		if (SSL_set_fd(d_ssl, d_fd) != 1) {
			d_state = STATE_FAIL;
			return build_error("ssl_connect::SSL_set_fd:", -1);
		}
		// ignore return
		SSL_set_tlsext_host_name(d_ssl, config::sni.c_str());
	}

	r = SSL_connect(d_ssl);
	d_ssl_e = ERR_peek_error();
	switch (SSL_get_error(d_ssl, r)) {
	case SSL_ERROR_NONE:
		return 1;
	// not ready yet? try later
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		return 0;
	}

	d_state = STATE_FAIL;
	return build_error("ssl_connect::SSL_connect:", -1);
}


int drops_peer::ssl_accept(SSL_CTX *ssl_ctx)
{
	int r = 0;

	if (!d_ssl) {
		if ((d_ssl = SSL_new(ssl_ctx)) == nullptr) {
			d_state = STATE_FAIL;
			return build_error("ssl_accept::SSL_new:", -1);
		}
		if (SSL_set_fd(d_ssl, d_fd) != 1) {
			d_state = STATE_FAIL;
			return build_error("ssl_accept::SSL_set_fd:", -1);
		}
	}

	r = SSL_accept(d_ssl);
	d_ssl_e = ERR_peek_error();
	switch (SSL_get_error(d_ssl, r)) {
	case SSL_ERROR_NONE:
		d_was_accept = 1;
		return 1;
	// not ready yet? try later
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		return 0;
	}

	d_state = STATE_FAIL;
	return build_error("ssl_accept::SSL_accept:", -1);
}



}

