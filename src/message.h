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

#ifndef drops_message_h
#define drops_message_h

#include <errno.h>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ftw.h>
#include "numbers.h"


extern "C" {
#include <openssl/err.h>
#include <openssl/evp.h>
}


namespace drops {

class drops_store {

	std::string d_base{""}, d_err{""}, d_tag{""};

	// hex id  -> content + date
	std::map<std::string, std::pair<std::string, time_t>> d_id2msg;

	std::string::size_type d_cache_size{0};

	unsigned long d_ssl_e{0};

	int d_idfd{-1};

	time_t d_now{0};

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		unsigned long e = 0;

		d_err = "drops_store::";
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


	int index(const std::string &);

public:

	friend int walk(const char *, const struct stat *, int, struct FTW *);

	typedef off_t iterator;

	drops_store(std::string &cfg, std::string &t)
	: d_base(cfg), d_tag(t)
	{
		d_now = ::time(nullptr);
	}

	~drops_store()
	{
	}

	int init();

	const char *why()
	{
		return d_err.c_str();
	}

	int store(const std::string &, const std::string &, time_t t = 0);

	int store_inq(const std::string &, const std::string &);

	int load(const std::string &, std::string &);

	int load_outq(std::string &, std::string &);

	int build_index();

	void update_time(time_t t = 0)
	{
		if (!t)
			d_now = ::time(nullptr);
		else
			d_now = t;
	}

	drops_store::iterator fetch_inc(drops_store::iterator, std::string &);

	drops_store::iterator begin()
	{
		return 0;
	}

	drops_store::iterator end()
	{
		if (d_idfd < 0)
			return 0;
		struct stat st;
		if (fstat(d_idfd, &st) < 0)
			return 0;
		return st.st_size;
	}

	bool has_id(const std::string &);

	bool maybe_cache_clear();

};


class msg_filter {

	std::map<std::string, std::string> d_filters;

public:

	msg_filter()
	{
	}

	~msg_filter()
	{
	}

	void add_filter(const std::string &s, const std::string &d)
	{
		d_filters[s] = d;
	}

	bool filter(const std::string &);

};


time_t cloak_date(time_t);

int sign_message(std::string &, const Numbers::submit_key *const, time_t);

int verify_message(const std::string &, EVP_PKEY *, const std::string &);


}


#endif

