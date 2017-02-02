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

#ifndef drops_ssl_h
#define drops_ssl_h

#include <string>
#include <errno.h>
#include <cstring>

extern "C" {
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>
}

namespace drops {

class ssl_container {

	unsigned long d_ssl_e{0};

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	const SSL_METHOD *ssl_s_method{nullptr}, *ssl_c_method{nullptr};
#else
	SSL_METHOD *ssl_s_method{nullptr}, ssl_c_method{nullptr};
#endif

	SSL_CTX *d_sctx{nullptr}, *d_cctx{nullptr};

	std::string d_err{""};

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		unsigned long e = 0;

		d_err = "ssl_container::";
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

	ssl_container()
	{
	}

	~ssl_container()
	{
		SSL_CTX_free(d_sctx);
		SSL_CTX_free(d_cctx);
	}

	const char *why()
	{
		return d_err.c_str();
	}

	int init(const std::string &, const std::string &, const std::string &);

	SSL_CTX *sctx() const
	{
		return d_sctx;
	}

	SSL_CTX *cctx() const
	{
		return d_cctx;
	}

	void clear();

};

}

#endif

