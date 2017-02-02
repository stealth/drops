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

#ifndef drops_drops_h
#define drops_drops_h

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <utility>
#include <stdint.h>
#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <netdb.h>
#include "misc.h"
#include "peer.h"
#include "message.h"
#include "ssl.h"


extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
}


namespace drops {


class log {

	FILE *f{nullptr};

public:

	log()
	{
	}

	~log()
	{
		if (f)
			fclose(f);
	}

	int init(const std::string &);

	int logit(const std::string &, const std::string &, time_t t = 0);

};



class drops_engine {

	std::string d_err{""}, d_tag{"global"}, d_id{""}, d_base{""};

	std::map<std::string, int> d_peer_ids{};

	std::string d_cpath{""}, d_kpath{""}, d_capath{""};

	log d_log;

	drops_store::iterator d_store_idx;
	drops_store *d_store{nullptr};

	drops_peer **d_peers{nullptr};
	struct pollfd *d_pfds{nullptr};

	int d_max_fd{-1}, d_first_fd{-1}, d_npeers{0};
	const int d_min_peers{20};

	addrinfo *d_baddr{nullptr};	// where to bind to

	unsigned int d_version = 1;

	unsigned long d_ssl_e{0};	// cached last SSL error

	time_t d_now{0};

	int d_has_new_msg{0};

	bool d_has_new_nodes{0};

	// nodes that we are actuallya connected to
	std::map<std::string, std::pair<time_t, time_t>> d_connected_nodes;

	// All valid/responsive nodes that we are aware of, includes learned
	// nodes from other peers and which are not yet connected
	std::map<std::string, std::pair<time_t, time_t>> d_learned_nodes;

	std::map<std::string, time_t> d_myaddrs;


	ssl_container *sslc{nullptr};

	void calc_max_fd();

	int cleanup(int, time_t t = 0);

	class drops_peer *connect(const std::string &, const std::string &);

	class drops_peer *connect(const std::string &, uint16_t);

	class drops_peer *connect(const std::string &);

	std::ostringstream &append_cnodes(std::ostringstream &);

	int parse_handshake(drops_peer *, const std::string &);

	int parse_pingpong_msg(drops_peer *, const std::string &);

	std::ostringstream &next_pingpong_msg(drops_peer *, std::ostringstream &);

	int nodes_from_store();

	int nodes_to_store();

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		unsigned long e = 0;

		d_err = "drops_engine::";
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

	drops_engine(const std::string &cfg)
	{
		d_base = cfg;

		d_capath = "ca.pem";
		d_cpath = "cert.pem";
		d_kpath = "key.pem";
	}

	~drops_engine()
	{
		if (d_baddr)
			freeaddrinfo(d_baddr);

		delete [] d_peers;
		delete [] d_pfds;

		delete d_store;
	}

	const char *why()
	{
		return d_err.c_str();
	}

	int init(const std::string &, const std::string &, const std::string &, const std::string &tag = "global");

	int boot_node(const std::string &n)
	{
		d_learned_nodes[n] = std::make_pair(timeouts::initial, time(nullptr));
		return 0;
	}

	int loop();
};



}


#endif


