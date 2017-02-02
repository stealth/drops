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

#ifndef drops_deleters_h
#define drops_deleters_h

#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>
#include <netdb.h>

extern "C" {
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
}

#include <cstdio>

namespace drops {

extern "C" typedef void (*EVP_PKEY_del)(EVP_PKEY *);

extern "C" typedef void (*EVP_PKEY_CTX_del)(EVP_PKEY_CTX *);

extern "C" typedef void (*EVP_MD_CTX_del)(EVP_MD_CTX *);

extern "C" typedef void (*EVP_CIPHER_CTX_del)(EVP_CIPHER_CTX *);

extern "C" typedef void (*DH_del)(DH *);

extern "C" typedef void (*RSA_del)(RSA *);

extern "C" typedef void (*DSA_del)(DSA *);

extern "C" typedef int (*BIO_del)(BIO *);

extern "C" typedef void (*BIGNUM_del)(BIGNUM *);

extern "C" typedef void (*BN_CTX_del)(BN_CTX *);

extern "C" typedef void (*BN_GENCB_del)(BN_GENCB *);

extern "C" typedef void (*EC_GROUP_del)(EC_GROUP *);

extern "C" typedef void (*EC_KEY_del)(EC_KEY *);

extern "C" typedef void (*EC_POINT_del)(EC_POINT *);

extern "C" typedef int (*FILE_del)(FILE *);

extern "C" typedef void (*free_del)(void *);

extern "C" typedef void (*addrinfo_del)(addrinfo *);

extern "C" typedef int (*DIR_del)(DIR *);

// for OpenSSL stupidity on sharing SSL err queue with EVP/RSA
// Err queue
class ERR_clear
{
public:
	ERR_clear()
	{
	}

	~ERR_clear()
	{
		ERR_clear_error();
	}
};


}

#endif
