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
#include <vector>
#include <string>
#include <cstdio>
#include <memory>
#include <cstring>
#include "misc.h"
#include "missing.h"
#include "deleters.h"

extern "C" {
#include <openssl/evp.h>
}

using namespace std;


namespace drops {


// WHAT?? gcc optimizes this away if not also declared "extern". This is bullshit.
// extern declared variables in header files are _known_ to be used by other modules,
// so why is this necessary?
unsigned int max_msg_size = 100*1024;


string &blob2hexhash(const string &blob, string &hex)
{
	hex = "";

	unsigned char digest[32] = {0}, digest2[32] = {0}, *dptr = digest;
	const void *ptr = blob.c_str();
	unsigned int hlen = blob.size();

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
	if (!md_ctx.get())
		return hex;
	for (int i = 0; i < 2; ++i) {
		if (EVP_DigestInit_ex(md_ctx.get(), EVP_sha256(), nullptr) != 1)
			return hex;
		if (EVP_DigestUpdate(md_ctx.get(), ptr, hlen) != 1)
			return hex;
		if (EVP_DigestFinal_ex(md_ctx.get(), dptr, &hlen) != 1)
			return hex;
		ptr = digest;
		dptr = digest2;
	}

	return blob2hex(string(reinterpret_cast<char *>(digest2), sizeof(digest2)), hex);
}


// first 32bytes of hexhash
string &blob2hexid(const string &blob, string &r)
{
	r = "";
	string hex = "";
	blob2hexhash(blob, hex);
	if (hex.size() < 32)
		return r;
	r = hex.substr(0, 32);
	return r;
}


string &blob2hex(const string &blob, string &hex)
{
	char h[3];

	hex = "";
	for (string::size_type i = 0; i < blob.size(); ++i) {
		snprintf(h, sizeof(h), "%02x", 0xff&blob[i]);
		hex += h;
	}
	return hex;
}

// only lowercase hex
bool is_hex_hash(const string &s)
{
	if (s.size() % 2 != 0 || s.size() < 32 || s.size() > 128)
		return 0;

	for (string::size_type i = 0; i < s.size(); ++i) {
		if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
			return 0;
	}
	return 1;
}


bool is_valid_have(const string &s)
{
	if (s == "nothing")
		return 1;
	return is_hex_hash(s);
}



} // namespace

