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

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

#include "dh2048.cc"


static DH *dh2048 = NULL;


DH *dh_callback(SSL *ssl, int is_exported, int keylen)
{
	return dh2048;
}


int enable_dh(SSL_CTX *ctx)
{
	if ((dh2048 = get_dh2048()) != NULL) {
		SSL_CTX_set_tmp_dh_callback(ctx, dh_callback);
		return 1;
	}
	return 0;
}

