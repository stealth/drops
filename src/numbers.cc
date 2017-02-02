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

#include <string>
#include <time.h>
#include <memory>
#include <iostream>
#include <map>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include "misc.h"
#include "base64.h"
#include "numbers.h"
#include "missing.h"
#include "deleters.h"


extern "C" {
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
}


#include <iostream>

namespace drops {


Numbers *numbers{nullptr};

using namespace std;


// This function is not using build_error(), as d_err would
// be a shrared, unlocked, resource
Numbers::submit_key *Numbers::get1(time_t t)
{
	submit_key *sk = nullptr;

	time_t now = time(nullptr);
	if (now < d_drops_epoch)
		return sk;

	if (d_nkeys.load() == 0) {
		d_keys_cond.notify_one();
		return sk;
	}

	lock_guard<mutex> lk(d_keys_lck);

	for (auto i = d_keys.begin(); i != d_keys.end();) {
		if (bits_of_then(t) != bits_of_then(i->second)) {
			i = d_keys.erase(i);
			d_nkeys.fetch_sub(1);
			continue;
		}

		sk = i->first;
		d_keys.erase(i);
		break;
	}

	if (sk)
		d_nkeys.fetch_sub(1);

	if (d_nkeys.load() < 5)
		d_keys_cond.notify_one();

	return sk;
}


uint32_t bits_of_then(time_t t)
{
	if (t <= Numbers::d_drops_epoch)
		return 0xffffffff;

	uint32_t rsa_bits = Numbers::d_rsa_bitsize + ((t - Numbers::d_drops_epoch)/one_day);
	return rsa_bits;
}


uint32_t bits_of_today()
{
	uint32_t today_rsa_bits = Numbers::d_rsa_bitsize + ((time(nullptr) - Numbers::d_drops_epoch)/one_day);
	return today_rsa_bits;
}


int Numbers::gen1()
{
	time_t now = time(nullptr);
	if (now < d_drops_epoch)
		return build_error("gen1: Timewarp??", -1);
	int rsa_bits = bits_of_then(now);

	unique_ptr<RSA, RSA_del> rsa(RSA_new(), RSA_free);
	if (!rsa.get())
		return build_error("gen1: OOM", -1);
	if (RSA_generate_key_ex(rsa.get(), rsa_bits, d_e, nullptr) != 1)
		return build_error("gen1::RSA_generate_key_ex:", -1);

	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(EVP_PKEY_new(), EVP_PKEY_free);
	unique_ptr<BIO, BIO_del> bio(BIO_new(BIO_s_mem()), BIO_free);
	if (!evp.get() || !bio.get())
		return build_error("gen1: OOM", -1);

	if (EVP_PKEY_set1_RSA(evp.get(), rsa.get()) != 1)
		return build_error("gen1::EVP_PKEY_set1_RSA: ", -1);

	if (PEM_write_bio_PUBKEY(bio.get(), evp.get()) != 1)
		return build_error("gen1::PEM_write_bio_PUBKEY: ", -1);

	const BIGNUM *bn_n = nullptr;
	drops::RSA_get0_key(rsa.get(), &bn_n, nullptr, nullptr);

	int nlen = BN_num_bytes(bn_n);
	if (nlen <= 0)
		return build_error("gen1: OOM", -1);
	unique_ptr<unsigned char[]> bin(new (nothrow) unsigned char[nlen]);
	if (!bin.get())
		return build_error("gen1: OOM", -1);
	if (BN_bn2bin(bn_n, bin.get()) != nlen)
		return build_error("gen1::BN_bn2bin:", -1);

	char *ptr = nullptr;
	long l = BIO_get_mem_data(bio.get(), &ptr);
	submit_key *sk = new (nothrow) submit_key;
	if (!sk)
		return build_error("gen1: OOM", -1);

	sk->pem_pkey = string(ptr, l);
	sk->pkey = evp.release();
	blob2hexid(string(reinterpret_cast<char *>(bin.get()), nlen), sk->id);
	sk->time = now;

	unique_lock<mutex> lk(d_keys_lck);
	d_keys[sk] = now;
	d_nkeys.fetch_add(1);
	d_keys_cond.wait(lk, [this]{return d_nkeys.load() <= 10;});

	return 0;
}



EVP_PKEY *check_numbers(const string &pem, const string &id, time_t msg_date, time_t now)
{

	// This is a trick to clear SSL's error queue (to not interfer with
	// SSL_read/write returns), in case an error occurs on the libcrypto
	// PEM/RSA functions. Somewhat an OpenSSL bug to have the same error queue for
	// everything
	ERR_clear ec;

	unique_ptr<char, free_del> sdup(strdup(pem.c_str()), free);
	if (!sdup.get())
		return nullptr;
	unique_ptr<BIO, BIO_del> bio(BIO_new_mem_buf(sdup.get(), pem.size()), BIO_free);
	if (!bio.get())
		return nullptr;
	unique_ptr<EVP_PKEY, EVP_PKEY_del> evp(nullptr, EVP_PKEY_free);
	evp.reset(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
	if (!evp.get())
		return nullptr;
	if (EVP_PKEY_base_id(evp.get()) != EVP_PKEY_RSA)
		return nullptr;

	int want_rsa_bits = bits_of_then(msg_date);
	int today_rsa_bits = bits_of_then(now);

	unique_ptr<RSA, RSA_del> rsa(EVP_PKEY_get1_RSA(evp.get()), RSA_free);
	if (!rsa.get())
		return nullptr;
	int rsa_bits = RSA_bits(rsa.get());
	const BIGNUM *n = nullptr, *e1 = nullptr;
	drops::RSA_get0_key(rsa.get(), &n, &e1, nullptr);

	BIGNUM *e2 = nullptr;
	if (BN_dec2bn(&e2, "65537") == 0)
		return nullptr;

	bool same_e = (BN_cmp(e1, e2) == 0);
	BN_free(e2);

	if (want_rsa_bits != rsa_bits || !same_e)
		return nullptr;

	// No more than 1day ahead or 12days before
	if (rsa_bits > today_rsa_bits) {
		if (rsa_bits - today_rsa_bits > 1)
			return nullptr;
	} else if (today_rsa_bits - rsa_bits > 12)
			return nullptr;

	// last, check hash id
	int nlen = BN_num_bytes(n);
	if (nlen <= 0)
		return nullptr;
	unique_ptr<unsigned char[]> bin(new (nothrow) unsigned char[nlen]);
	if (!bin.get())
		return nullptr;
	if (BN_bn2bin(n, bin.get()) != nlen)
		return nullptr;

	string s = "";
	if (blob2hexid(string(reinterpret_cast<char *>(bin.get()), nlen), s) != id)
		return nullptr;

	return evp.release();
}


}


