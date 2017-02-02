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

#define _POSIX_C_SOURCE 200809L
#include <cstdio>
#include <string>
#include <memory>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <iostream>

#include "message.h"
#include "numbers.h"
#include "deleters.h"
#include "config.h"
#include "base64.h"
#include "misc.h"
#include "missing.h"

using namespace std;


namespace drops {


int drops_store::init()
{
	if (d_tag != "global" && !is_hex_hash(d_tag))
		return build_error("init: Invalid drops tag.", -1);

	string path = d_base + "/" + d_tag;

	string inq = path + "/inq";
	mkdir(inq.c_str(), 0700);
	string outq = path + "/outq";
	mkdir(outq.c_str(), 0700);
	string fl = path + "/flying";
	mkdir(fl.c_str(), 0700);

	string idx_path = path + "/flight.idx";
	if ((d_idfd = open(idx_path.c_str(), O_RDWR|O_CREAT, 0600)) < 0)
		return build_error("init::open:", -1);

	return 0;
}


// find next usable message id and increase iterator to point to next new
// id
drops_store::iterator drops_store::fetch_inc(drops_store::iterator i, string &hex)
{
	string s1 = "", s2 = "";
	string::size_type idx1 = string::npos, idx2 = string::npos;

	hex = "nothing";

	char buf[512] = {0};
	ssize_t n = 0;
	for (;;) {
		memset(buf, 0, sizeof(buf));

		// If end of file, its the last index so far
		if ((n = pread(d_idfd, buf, sizeof(buf) - 1, i)) == 0)
			return i;
		s1 = buf;
		if ((idx1 = s1.find(",")) == string::npos || idx1 < 32) {
			++i;
			continue;
		}
		s2 = s1.substr(0, idx1);
		++idx1;
		i += idx1;

		if ((idx2 = s1.find(",", idx1)) == string::npos)
			continue;
		i += (idx2 - idx1) + 2;	// +1 for newline
		time_t date = (time_t)strtoull(s1.c_str() + idx1, nullptr, 10);
		if ((date < d_now && d_now - date > ten_days) ||
		    (d_now < date && date - d_now > one_day))
			continue;
		hex = s2;
		break;
	}

	return i;
}


// message id "hex" in cache or storage?
bool drops_store::has_id(const string &hex)
{
	if (!is_hex_hash(hex))
		return 0;

	if (d_id2msg.count(hex) > 0)
		return 1;

	string path = d_base + "/" + d_tag + "/flying/" + hex.substr(0, 4) + "/" + hex;
	struct stat st;
	if (stat(path.c_str(), &st) != 0)
		return 0;

	// date 0 indicates, no content load yet and therefore we dont know actual date
	d_id2msg[hex] = make_pair("", 0);
	d_cache_size += (sizeof(time_t) + hex.size());
	return 1;
}


// Add msg id to index file to be used by iterator
int drops_store::index(const string &hex)
{
	if (!is_hex_hash(hex))
		return build_error("cache: Not a valid hex string.", -1);

	string path = d_base + "/" + d_tag + "/flying/" + hex.substr(0, 4) + "/" + hex;

	int fd = open(path.c_str(), O_RDONLY);
	if (fd < 0)
		return build_error("cache::open:", -1);

	char buf[8192 + 1] = {0};
	ssize_t r = 0;
	if ((r = read(fd, buf, sizeof(buf) - 1)) <= 0) {
		close(fd);
		return build_error("index_one::read:", -1);
	}
	close(fd);

	string msg = string(buf, r);


	// Its ok to parse message date from storage on disk, since its signature
	// and key sanity was checked when it was saved. And you wont mess up your
	// own setup by modifying it, wont you?
	string::size_type idx = msg.find("date=");
	if (idx == string::npos)
		return build_error("cache: Invalid msg format", -1);
	idx += 5;
	string::size_type comma = msg.find(",", idx);
	if (comma == string::npos)
		return build_error("cache: Invalid msg format", -1);

	time_t date = (time_t)strtoull(msg.substr(idx, comma - idx).c_str(), nullptr, 10);
	if (date < d_now) {
		// dont load messages older than 10 days
		if (d_now - date > ten_days) {
			if (d_now - date > twelve_days)
				unlink(path.c_str());
			return 0;
		}
	}

	int n = snprintf(buf, sizeof(buf) - 1, "%s,%016llu,\n", hex.c_str(), (unsigned long long)date);
	if (n > 0)
		write(d_idfd, buf, n);

	return 1;
}


// load message of id "hex", and use/populate message cache while doing so
int drops_store::load(const string &hex, string &msg)
{
	msg = "";

	if (!is_hex_hash(hex))
		return build_error("load: Not a valid hex string.", -1);

	auto i = d_id2msg.find(hex);
	if (i != d_id2msg.end()) {
		time_t date = i->second.second;
		if (date < d_now && d_now - date <= ten_days) {
			msg = i->second.first;
			return 1;
		} else if (d_now < date && date - d_now <= one_day) {
			msg = i->second.first;
			return 1;
		}

		// date 0 means, we have the file (found via has_id(), but didnt load it yet)
		if (date != 0)
			return 0;
	}

	string path = d_base + "/" + d_tag + "/flying/" + hex.substr(0, 4) + "/" + hex;
	unique_ptr<FILE, FILE_del> f(fopen(path.c_str(), "r"), fclose);

	char buf[4096] = {0};
	ssize_t r = 0;
	do {
		if ((r = read(fileno(f.get()), buf, sizeof(buf))) < 0)
			return build_error("load::read:", -1);
		if (r > 0)
			msg += string(buf, r);
		if (msg.size() > max_msg_size)
			return build_error("load::read:", -1);
	} while (r > 0);

	f.reset();

	string::size_type idx = msg.find(",date=");
	if (idx == string::npos)
		return build_error("load: Invalid msg format", -1);
	idx += 6;
	string::size_type comma = msg.find(",", idx);
	if (comma == string::npos)
		return build_error("load: Invalid msg format", -1);

	time_t date = (time_t)strtoull(msg.substr(idx, comma - idx).c_str(), nullptr, 10);

	// if its already with 0-date in cache, the size was already counted
	if (i == d_id2msg.end())
		d_cache_size += (sizeof(date) + hex.size());

	d_id2msg[hex] = make_pair("", date);

	if ((date < d_now && d_now - date > ten_days) ||
	    (d_now < date && date - d_now > one_day))
		return 0;

	d_id2msg[hex].first = msg;
	d_cache_size += msg.size();

	return 1;
}


drops_store *bs = nullptr;

int walk(const char *path, const struct stat *st, int typeflag, struct FTW *ftwbuf)
{
	if (!bs)
		return -1;

	if (typeflag == FTW_F) {
		string p = path;
		auto idx = p.find_last_of("/");
		if (idx != string::npos)
			p.erase(0, idx + 1);
		if (S_ISREG(st->st_mode) && is_hex_hash(p))
			bs->index(p);
	}
	return 0;
}


// create index file for storage
int drops_store::build_index()
{
	if (d_idfd < 0)
		build_error("build_index:: ->init() not called?!", -1);
	ftruncate(d_idfd, 0);

	bs = this;
	string path = d_base + "/" + d_tag + "/flying";
	nftw(path.c_str(), walk, 1024, FTW_PHYS);
	bs = nullptr;
	return 0;
}


// store one msg of id "hex" and populate cache while doing so
int drops_store::store(const string &hex, const string &msg, time_t date)
{
	int fd = -1;

	if (!is_hex_hash(hex))
		return build_error("store: Not a valid hex string.", -1);

	if (d_id2msg.count(hex) > 0)
		return 0;

	string path = d_base + "/" + d_tag + "/flying/" + hex.substr(0, 4);
	mkdir(path.c_str(), 0700);
	path += "/";
	path += hex;

	if ((fd = open(path.c_str(), O_WRONLY|O_CREAT|O_EXCL, 0600)) < 0) {
		if (errno != EEXIST)
			return build_error("store::open:", -1);
		return 0;
	}
	if (write(fd, msg.c_str(), msg.size()) != (ssize_t)msg.size()) {
		close(fd);
		return build_error("store::write:", -1);
	}
	close(fd);

	// No message date given? Parse ourselfes
	if (date == 0) {
		string::size_type idx = msg.find(",date=");
		if (idx == string::npos)
			return build_error("store: Invalid msg format", -1);
		idx += 6;
		string::size_type comma = msg.find(",", idx);
		if (comma == string::npos)
			return build_error("store: Invalid msg format", -1);

		date = (time_t)strtoull(msg.substr(idx, comma - idx).c_str(), nullptr, 10);
	}

	char buf[512] = {0};
	snprintf(buf, sizeof(buf) - 1, "%s,%016llu,\n", hex.c_str(), (unsigned long long)date);

	// Write() increases indexfile offset and always points to end.
	// The iterator fetch_inc() is stateless, as iterator (offset) is hold
	// by caller and therefore independent from this write().
	write(d_idfd, buf, strlen(buf));

	d_id2msg[hex] = make_pair(msg, date);
	d_cache_size += (sizeof(date) + hex.size() + msg.size());
	return 1;
}


int drops_store::store_inq(const string &hex, const string &msg)
{
	int fd = -1;

	if (!is_hex_hash(hex))
		return build_error("store_in: Not a valid hex string.", -1);

	string path = d_base + "/" + d_tag + "/inq/" + hex;

	if ((fd = open(path.c_str(), O_WRONLY|O_CREAT|O_EXCL, 0600)) < 0)
			return build_error("store_in::open:", -1);
	ssize_t wn = write(fd, msg.c_str(), msg.size());
	close(fd);

	if (wn != (ssize_t)msg.size())
		return build_error("store_in::write:", -1);

	return 0;
}


bool drops_store::maybe_cache_clear()
{
	if (d_cache_size < config::max_cache_size)
		return 0;

	d_id2msg.clear();
	d_cache_size = 0;
	return 1;
}


// load next message from out queue
int drops_store::load_outq(string &msg, string &p)
{
	msg = "";
	p = "";

	string path = d_base + "/" + d_tag + "/outq";

	unique_ptr<DIR, DIR_del> dp(opendir(path.c_str()), closedir);
	struct dirent *de = nullptr;
	if (!dp.get())
		return build_error("load_outq:", -1);

	for (;;) {
		if (!(de = readdir(dp.get())))
			break;
		if (strlen(de->d_name) < 7)
			continue;
		if (strcmp(de->d_name + strlen(de->d_name) - 6, ".opmsg") == 0) {
			p = path + "/" + de->d_name;
			int fd = open(p.c_str(), O_RDONLY|O_NONBLOCK|O_NOCTTY);
			if (fd < 0)
				continue;
			char buf[4096] = {0};
			ssize_t r = 0;
			for (;;) {
				if ((r = read(fd, buf, sizeof(buf))) < 0) {
					close(fd);
					return build_error("load_outq::read:", -1);
				}
				msg += string(buf, r);
				if (r < (ssize_t)sizeof(buf))
					break;
			}
			close(fd);
		}

		// some safety checks so nobody is accidently throwing /etc/passwd away
		if (msg.find("-----BEGIN OPMSG-----") != 0)
			continue;
		if (msg.find("-----END OPMSG-----") == string::npos)
			continue;

		break;
	}

	return 0;
}


bool msg_filter::filter(const string &msg)
{
	string::size_type si = msg.find("src-id="), di = msg.find("dst-id="), nl = 0;
	if (si == string::npos || di == string::npos)
		return 0;
	si += 7; di += 7;
	if ((nl = msg.find("\n", si)) == string::npos)
		return 0;

	string src_id = msg.substr(si, nl - si);

	if ((nl = msg.find("\n", di)) == string::npos)
		return 0;

	string dst_id = msg.substr(di, nl - di);


	for (auto i : d_filters) {
		if (i.first.size() > 0 && src_id.find(i.first) == string::npos)
			continue;
		if (i.second.size() == 0)
			return 1;
		if (dst_id.find(i.second) != string::npos)
			return 1;
	}

	return 0;
}


// cloak some minutes so its unclear whether we injected the message
// or are forwarding on other dropss behalf
time_t cloak_date(time_t t)
{
	return (t & ~0xff);
}


// construct a drops message from a plain opmsg
int sign_message(string &msg, const Numbers::submit_key *const sk, time_t date)
{
	// This is a trick to clear SSL's error queue (to not interfer with
	// SSL_read/write returns), in case an error occurs on the libcrypto
	// PEM/RSA functions. Somewhat an OpenSSL bug to have the same error queue for
	// everything
	ERR_clear ec;

	// date must be already cloaked by caller
	char buf[32] = {0};
	snprintf(buf, sizeof(buf) - 1, "%016llu", (unsigned long long)date);
	string sdate = buf;

	msg += ",end}\n";
	msg.insert(0, "msgid=" + sk->id + ",\n");
	msg.insert(0, "rsakey=\n" + sk->pem_pkey + ",");
	msg.insert(0, "date=" + sdate + ",");

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
	if (!md_ctx.get())
		return -1;
	if (EVP_DigestSignInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, sk->pkey) != 1)
		return -1;
	if (EVP_DigestSignUpdate(md_ctx.get(), msg.c_str(), msg.size()) != 1)
		return -1;
	size_t siglen = 0;
	if (EVP_DigestSignFinal(md_ctx.get(), nullptr, &siglen) != 1 || siglen > 32000)
		return -1;

	unique_ptr<unsigned char[]> sig(new (nothrow) unsigned char[siglen]);
	if (!sig.get() || EVP_DigestSignFinal(md_ctx.get(), sig.get(), &siglen) != 1)
		return -1;

	string b64sig = "";
	b64_encode(reinterpret_cast<char *>(sig.get()), siglen, b64sig);
	if (b64sig.empty())
		return -1;
	msg.insert(0, "rsasig=" + b64sig + ",");

	return 0;
}


int verify_message(const string &msg, EVP_PKEY *key, const string &b64sig)
{
	// This is a trick to clear SSL's error queue (to not interfer with
	// SSL_read/write returns), in case an error occurs on the libcrypto
	// PEM/RSA functions. Somewhat an OpenSSL bug to have the same error queue for
	// everything
	ERR_clear ec;

	// signature starts at offset 0
	if (msg.find("rsasig=") != 0)
		return 0;
	string::size_type comma = msg.find(",");
	if (comma == string::npos)
		return 0;

	if (msg.substr(7, comma - 7) != b64sig)
		return 0;

	string sig = "";
	b64_decode(b64sig, sig);
	if (!sig.size())
		return 0;

	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
	if (!md_ctx.get())
		return 0;
	if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, key) != 1)
		return 0;
	if (EVP_DigestVerifyUpdate(md_ctx.get(), msg.c_str() + comma + 1, msg.size() - comma - 1) != 1)
		return 0;
	if (EVP_DigestVerifyFinal(md_ctx.get(), (unsigned char *)(sig.c_str()), sig.size()) != 1)
		return 0;

	return 1;
}


}

