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

#ifndef drops_peer_h
#define drops_peer_h

#include <string>
#include <cstring>
#include <stdint.h>
#include <cstdlib>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include "message.h"


extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
}


namespace drops {


enum drops_peer_state {
	STATE_NONE			= 0,
	STATE_FAIL,
	STATE_CONNECTING,
	STATE_CONNECT_DONE,
	STATE_SSL_CONNECT_DONE,
	STATE_ACCEPTING,
	STATE_ACCEPT_DONE,
	STATE_HANDSHAKE_RCV,
	STATE_HANDSHAKE_SND,
	STATE_PINGPONG_RCV,
	STATE_PINGPONG_SND,
	STATE_PINGPONG_SLEEP
};



class drops_peer {

	std::string d_err{""};

	std::string d_rmsg{""}, d_smsg{""};
	SSL *d_ssl{nullptr};

	bool d_was_accept{0};

	std::string d_lasthave{""}, d_lastoffer{""};
	bool d_wants_lastoffer{0};

	std::string d_ip{""}, d_node{""};
	uint16_t d_port{0};

	std::string d_id{""};

	int d_fd{-1};
	int d_af{AF_UNSPEC};

	uint32_t d_fails{0};
	const uint32_t d_max_fails{10};

	time_t d_timer{0};

	unsigned long d_ssl_e{0};

	drops_peer_state d_state{STATE_NONE};

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		unsigned long e = 0;

		d_err = "drops_peer::";
		d_err += msg;
		if ((e = ERR_get_error()) || d_ssl_e) {
			if (e == 0)
				e = d_ssl_e;
			d_err += ":";
			d_err += ERR_error_string(e, nullptr);
			ERR_clear_error();
			d_ssl_e = 0;
		} else if (errno) {
			d_err += ":";
			d_err += strerror(errno);
		}
		errno = 0;
		return r;
	}


public:

	// received all bs-msgs up to (excluding) this index
	uint64_t d_store_idx{0};

	drops_peer(const std::string &s, uint16_t p, int f, int af)
		: d_ip(s), d_port(p), d_fd(f), d_af(af)
	{
		char buf[256] = {0};
		snprintf(buf, sizeof(buf) - 1, "[%s]:%hu", s.c_str(), p);
		d_node = buf;
	}

	drops_peer(const std::string &s, const std::string &p, int f, int af)
		: d_ip(s), d_fd(f), d_af(af)
	{
		d_port = (uint16_t)strtoul(p.c_str(), nullptr, 10);
		d_node = "[" + s + "]:" + p;
	}


	~drops_peer()
	{
		this->reset();
	}

	const char *why() const
	{
		return d_err.c_str();
	}

	std::string ip() const
	{
		return d_ip;
	}

	std::string node() const
	{
		return d_node;
	}

	std::string sport() const
	{
		char s[32] = {0};
		snprintf(s, sizeof(s) - 1, "%hu", d_port);
		return std::string(s);
	}

	uint16_t port() const
	{
		return d_port;
	}

	std::string id() const
	{
		return d_id;
	}

	void id(std::string s)
	{
		d_id = s;
	}

	void timer(time_t t)
	{
		d_timer = t;
	}

	time_t timer() const
	{
		return d_timer;
	}

	drops_peer_state state() const
	{
		return d_state;
	}

	void state(drops_peer_state s)
	{
		d_state = s;
	}

	int fd() const
	{
		return d_fd;
	}

	bool is_write_done() const
	{
		return d_smsg.size() == 0;
	}

	bool is_read_done() const
	{
		if (d_rmsg.size() < 10)
			return 0;

		return d_rmsg.find(",end}\n", d_rmsg.size() - 7) != std::string::npos;
	}

	bool has_accepted() const
	{
		return d_was_accept;
	}

	std::string last_have() const
	{
		return d_lasthave;
	}

	void last_have(const std::string &s)
	{
		d_lasthave = s;
	}

	std::string last_offer() const
	{
		return d_lastoffer;
	}

	void last_offer(const std::string &s)
	{
		d_lastoffer = s;
	}

	bool wants_last_offer() const
	{
		return d_wants_lastoffer;
	}

	void wants_last_offer(bool b)
	{
		d_wants_lastoffer = b;
	}

	void reset()
	{
		close(d_fd);
		d_fd = -1;
		if (d_ssl)
			SSL_free(d_ssl);
		d_ssl = nullptr;
		d_lasthave = d_lastoffer = "";
		d_rmsg = d_smsg = "";
		d_was_accept = 0;
		d_af = AF_UNSPEC;
		d_ip = "";
		d_port = 0;
		d_state = STATE_NONE;
	}


	// read one drops msg from this peer
	int read1(short &);

	std::string &get_rmsg(std::string &r)
	{
		r = std::move(d_rmsg); d_rmsg = "";
		return r;
	}

	bool set_smsg(const std::string &s)
	{
		d_smsg = s;
		return 1;
	}

	// write one drops msg to this peer
	int write1(short &);

	int finish_connect();

	int ssl_connect(SSL_CTX *);

	drops_peer *accept(std::string &);

	int ssl_accept(SSL_CTX *);

	uint32_t fails(uint32_t f)
	{
		d_fails += f;
		return d_fails;
	}

	uint32_t max_fails()
	{
		return d_max_fails;
	}

};

}

#endif

