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

#include <map>
#include <string>
#include <unistd.h>
#include "missing.h"
#include "config.h"
#include "ssl.h"

extern "C" {
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>
}

extern int enable_dh(SSL_CTX *);

namespace drops {


using namespace std;

string ciphers = "!LOW:!EXP:!MD5:!CAMELLIA:!RC4:!MEDIUM:!DES:kDHE:!kRSA:AESGCM:AES256:AES128:SHA256:SHA384:IDEA:@STRENGTH";


// simple sanity check that local drops dont accidently connect
// to global drops. If you want authenticated local drops,
// setup your own CA and use your own ca.pem, cert.pem and key.pem in
// that local drops subdir
static int verify_callback(int ok, X509_STORE_CTX *store)
{
	X509 *x509 = X509_STORE_CTX_get0_cert(store);
	if (!x509)
		return 0;

	//  X509_get_subject_name() return must not be freed
	char subject[256] = {0};
	X509_NAME_oneline(X509_get_subject_name(x509), subject, sizeof(subject) - 1);
	if (config::tag != "global") {
		if (string(subject).find("local drop") == string::npos)
			return 0;
	} else {
		if (string(subject).find("global drop") == string::npos)
			return 0;
	}
	return ok;
}


int ssl_container::init(const string &capath, const string &cpath, const string &kpath)
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

	ERR_clear_error();

#if OPENSSL_VERSION_NUMBER >= 0x10100000
	if ((ssl_s_method = TLS_server_method()) == nullptr)
#else
	if ((ssl_s_method = SSLv23_server_method()) == nullptr)
#endif
		return build_error("init::server_method:", -1);

#if OPENSSL_VERSION_NUMBER >= 0x10100000
	if ((ssl_c_method = TLS_client_method()) == nullptr)
#else
	if ((ssl_c_method = SSLv23_client_method()) == nullptr)
#endif
		return build_error("init::client_method:", -1);

	long op = SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1;
	op |= (SSL_OP_SINGLE_DH_USE|SSL_OP_SINGLE_ECDH_USE);

	if ((d_sctx = SSL_CTX_new(ssl_s_method)) == nullptr)
		return build_error("init::SSL_CTX_new:", -1);

	if ((d_cctx = SSL_CTX_new(ssl_c_method)) == nullptr)
		return build_error("init::SSL_CTX_new:", -1);

	for (SSL_CTX *ctx : {d_sctx, d_cctx}) {

		if (SSL_CTX_load_verify_locations(ctx, capath.c_str(), nullptr) != 1)
			return build_error("init::SSL_CTX_load_verify_locations:", -1);
		if (SSL_CTX_use_certificate_file(ctx, cpath.c_str(), SSL_FILETYPE_PEM) != 1)
			return build_error("init::SSL_CTX_use_certificate_chain_file:", -1);
		if (SSL_CTX_use_PrivateKey_file(ctx, kpath.c_str(), SSL_FILETYPE_PEM) != 1)
			return build_error("init::SSL_CTX_use_PrivateKey_file:", -1);
		if (SSL_CTX_check_private_key(ctx) != 1)
			return build_error("init::SSL_CTX_check_private_key:", -1);

		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
		SSL_CTX_set_verify_depth(ctx, 3);
		SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);

		if ((unsigned long)(SSL_CTX_set_options(ctx, op) & op) != (unsigned long)op)
			return build_error("init::SSL_CTX_set_options:", -1);

		if (SSL_CTX_set_cipher_list(ctx, ciphers.c_str()) != 1)
			return build_error("init::SSL_CTX_set_cipher_list:", -1);

		enable_dh(ctx);
	}

	return 0;
}


void ssl_container::clear()
{
	SSL_CTX_free(d_sctx);
	SSL_CTX_free(d_cctx);
	d_sctx = d_cctx = nullptr;
}

}

