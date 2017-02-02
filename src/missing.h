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

#ifndef drops_missing_h
#define drops_missing_h



extern "C" {
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
}


#if OPENSSL_VERSION_NUMBER > 0x10100000L && !(defined HAVE_LIBRESSL)

/* Idiots... Not just they are renaming EVP_MD_CTX_destroy() to EVP_MD_CTX_free() in OpenSSL >= 1.1,
 * they define EVP_MD_CTX_destroy(ctx) macro along (with braces) so we cant define the symbol
 * ourself. Forces me to introduce an entirely new name to stay compatible with older
 * versions and libressl.
 */
#define EVP_MD_CTX_delete EVP_MD_CTX_free
#else
#define EVP_MD_CTX_delete EVP_MD_CTX_destroy
#endif


namespace drops {

#ifdef HAVE_BORINGSSL
int EVP_PKEY_base_id(const EVP_PKEY *pkey);
#endif

#if OPENSSL_VERSION_NUMBER <= 0x10100000L || defined HAVE_LIBRESSL || defined HAVE_BORINGSSL
int RSA_bits(const RSA *);

X509 *X509_STORE_CTX_get0_cert(X509_STORE_CTX *);
#endif

void RSA_get0_key(const RSA *r, const BIGNUM **, const BIGNUM **, const BIGNUM **);


}

#endif

