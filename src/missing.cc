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

extern "C" {
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
}


namespace drops {

#ifdef HAVE_BORINGSSL
int EVP_PKEY_base_id(const EVP_PKEY *pkey)
{
	return EVP_PKEY_type(pkey->type);
}
#endif

#if OPENSSL_VERSION_NUMBER <= 0x10100000L || defined HAVE_LIBRESSL || defined HAVE_BORINGSSL
void RSA_bits(const RSA *rsa)
{
	BN_num_bits(rsa->n);
}
#endif

void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
#if OPENSSL_VERSION_NUMBER <= 0x10100000L || defined HAVE_LIBRESSL || defined HAVE_BORINGSSL
	if (n)
		*n = r->n;
	if (e)
		*e = r->e;
	if (d)
		*d = r->d;
#elif OPENSSL_VERSION_NUMBER >= 0x1010001fL	// 1.1.0a
	::RSA_get0_key(r, n, e, d);
#else
	// Fuck OpenSSL for a) newly introducing this function in 1.1.0 without "const" and then
	// b) right in the middle defining it a few minor versions later as "const"
	::RSA_get0_key(r, const_cast<BIGNUM **>(n), const_cast<BIGNUM **>(e), const_cast<BIGNUM **>(d));
#endif
}

#if OPENSSL_VERSION_NUMBER <= 0x10100000L || defined HAVE_LIBRESSL || defined HAVE_BORINGSSL
X509 *X509_STORE_CTX_get0_cert(X509_STORE_CTX *ctx)
{
	return ctx->cert;
}
#endif

}

