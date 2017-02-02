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

#ifndef drops_numbers_h
#define drops_numbers_h

#include <cstring>
#include <errno.h>
#include <time.h>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <map>

extern "C" {
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
}


namespace drops {


class Numbers {

public:

	struct submit_key {
		EVP_PKEY *pkey{nullptr};
		std::string pem_pkey{""}, id{""};
		time_t time{0};

		submit_key()
		{
		}

		~submit_key()
		{
			if (pkey)
				EVP_PKEY_free(pkey);
		}
	};


	// somewhere Jan 1st 2017
	static const time_t d_drops_epoch{1483177350};

	// bitsize of the day for RSA at d_drops_epoch
	static const uint32_t d_rsa_bitsize{5000};


private:

	std::map<submit_key *, time_t> d_keys;
	mutable std::mutex d_keys_lck;

	std::atomic<unsigned int> d_nkeys{0};
	std::condition_variable d_keys_cond;


	BIGNUM *d_e{nullptr};

	unsigned long d_ssl_e{0};

	std::string d_err{""};

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		unsigned long e = 0;

		d_err = "Numbers::";
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


	Numbers()
	{
	}

	~Numbers()
	{
		for (auto i : d_keys)
			delete i.first;

		BN_free(d_e);
	}

	Numbers &operator=(const Numbers &) = delete;

	const char *why()
	{
		return d_err.c_str();
	}

	submit_key *get1(time_t);

	int gen1();

	int init()
	{
		if (RAND_load_file("/dev/urandom", 256) != 256)
			return -1;
		if (BN_dec2bn(&d_e, "65537") == 0)
			return -1;

		return 0;
	}

	unsigned int nkeys()
	{
		return d_nkeys.load();
	}

};


EVP_PKEY *check_numbers(const std::string &, const std::string &, time_t, time_t);

uint32_t bits_of_then(time_t);

uint32_t bits_of_today();

extern Numbers *numbers;

}


#endif

