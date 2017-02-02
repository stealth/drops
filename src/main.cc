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

#include <iostream>
#include <memory>
#include <thread>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include "drops.h"
#include "numbers.h"
#include "config.h"
#include "misc.h"


extern "C" {
#include <openssl/rand.h>
}

using namespace std;
using namespace drops;


string prefix = "drops: ", version = "version=0.1";


void usage(const char *s)
{
	cout<<"Usage: dropsd [--confdir dir] [--laddr] [--lport] [--newlocal] [-T tag] [--bootstrap node]\n\n"
	    <<"\t--confdir,\t-c\t(must come first) defaults to ~/.drops\n"
	    <<"\t--laddr,\t-l\tlocal IPv4/IPv6 address to bind to (default any)\n"
	    <<"\t--lport,\t-p\tlocal port (default "<<config::lport<<")\n"
	    <<"\t--newlocal,\t-N\tinitially set up a new local drops\n"
	    <<"\t--tag,\t\t-T\tdrops tag (defaults to 'global')\n"
	    <<"\t--bootstrap,\t-B\tbootstrap node if node file is empty and not initial local dropsd\n\n";

	exit(1);
}


// RAND_load_file() must have been called before calling this!
int nonce(string &id)
{
	id = "";

	char rnd[16] = {0};
	if (RAND_bytes(reinterpret_cast<unsigned char *>(rnd), sizeof(rnd)) != 1)
		return 1;

	blob2hexid(string(rnd, sizeof(rnd)), id);

	if (id.size() > 0)
		return 0;

	cerr<<prefix<<"Failed to generate nonce.";
	return -1;
}


int to_daemon()
{
	chdir("/");
	int fd = open("/dev/null", O_RDWR);
	dup2(fd, 0); dup2(fd, 1); close(fd);

	for (int i = 3; i < 1024; ++i)
		close(i);

	signal(SIGPIPE, SIG_IGN);

	pid_t pid = fork();
	if (pid > 0)
		exit(0);
	else if (pid < 0)
		return -1;

	setsid();
	return 0;
}


int copy_file(const string &from, const string &to)
{
	int fd1 = -1, fd2 = -1;

	if ((fd1 = open(from.c_str(), O_RDONLY)) < 0) {
		cerr<<prefix<<"Failed to open '"<<from<<"':"<<strerror(errno)<<endl;
		return -1;
	}
	if ((fd2 = open(to.c_str(), O_RDWR|O_CREAT, 0600)) < 0) {
		cerr<<prefix<<"Failed to open '"<<to<<"':"<<strerror(errno)<<endl;
		close(fd1);
		return -1;
	}

	char buf[32000] = {0};
	ssize_t r = sizeof(buf);
	for (;r == sizeof(buf);) {
		r = read(fd1, buf, sizeof(buf));
		if (r > 0)
			r = write(fd2, buf, r);
	}

	close(fd1);
	close(fd2);

	if (r < 0) {
		cerr<<prefix<<"Failed to copy files."<<strerror(errno)<<endl;
		return -1;
	}
	return 0;
}



int setup_local_drops(string &id)
{
	id = "";
	if (nonce(id) < 0)
		return -1;

	string lbs_dir = config::cfgbase + "/" + id;
	string tbs_dir = config::cfgbase + "/local";

	if (mkdir(lbs_dir.c_str(), 0700) < 0) {
		cerr<<prefix<<"Failed to create local drops dir '"<<lbs_dir<<"'"<<strerror(errno)<<endl;
		return -1;
	}
	if (mkdir((lbs_dir + "/outq").c_str(), 0700) < 0) {
		cerr<<prefix<<"Failed to create local drops dir '"<<lbs_dir<<"/outq'"<<strerror(errno)<<endl;
		return -1;
	}


	if (copy_file(tbs_dir + "/ca.pem", lbs_dir + "/ca.pem") < 0)
		return -1;
	if (copy_file(tbs_dir + "/cert.pem", lbs_dir + "/cert.pem") < 0)
		return -1;
	if (copy_file(tbs_dir + "/key.pem", lbs_dir + "/key.pem") < 0)
		return -1;

	return 0;
}



int main(int argc, char **argv)
{
	struct option lopts[] = {
		{"confdir", required_argument, nullptr, 'c'},
		{"laddr", required_argument, nullptr, 'l'},
		{"lport", required_argument, nullptr, 'p'},
		{"newlocal", no_argument, nullptr, 'N'},
		{"tag", required_argument, nullptr, 'T'},
		{"bootstrap", required_argument, nullptr, 'B'},
		{nullptr, 0, nullptr, 0}
	};
	int c = 0, opt_idx = 0;
	string boot_node = "";

	umask(077);

	cout<<"\n"<<prefix<<version<<" -- (C) 2017 Sebastian Krahmer https://github.com/stealth/drops\n\n";

	if (RAND_load_file("/dev/urandom", 256) != 256)
		return 1;

	if (getenv("HOME")) {
		config::cfgbase = getenv("HOME");
		config::cfgbase += "/.drops";
	}

	if (argc > 1 && (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--confdir") == 0)) {
		if (!argv[2])
			usage(argv[0]);
		config::cfgbase = argv[2];
	}

	if (parse_config(config::cfgbase) < 0)
		cerr<<prefix<<"WARN: failed to parse config file. Continuing.\n";

	while ((c = getopt_long(argc, argv, "l:p:c:T:B:N", lopts, &opt_idx)) != -1) {
		switch (c) {
		case 'l':
			config::laddr = optarg;
			break;
		case 'p':
			config::lport = optarg;
			break;
		case 'T':
			config::tag = optarg;
			if (!is_hex_hash(config::tag) && config::tag != "global") {
				cerr<<prefix<<"Invalid drops tag.\n";
				return -1;
			}
			break;
		case 'N':
			if (setup_local_drops(config::tag) < 0) {
				cerr<<prefix<<"Failed to create new local drops.\n";
				return -1;
			}
			cout<<prefix<<"Success setting up new local drops with tag "<<config::tag<<endl<<endl
			    <<prefix<<"You execute: dropsd -T "<<config::tag<<endl
			    <<prefix<<"All others execute: dropsd -T "<<config::tag<<" -B [yourip]:yourport\n\n";
			return 0;
		case 'B':
			boot_node = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}

	drops_engine *drops = new (nothrow) drops_engine(config::cfgbase);

	string id = "";
	if (nonce(id) < 0)
		return -1;

	cout<<prefix<<"Bits of today="<<bits_of_today()<<" id="<<id<<" tag="<<config::tag<<endl
	    <<prefix<<"laddr="<<config::laddr<<" lport="<<config::lport<<endl
	    <<prefix<<"Going background.\n\n";

	if (to_daemon() < 0)
		return 1;

	if (drops->init(config::laddr, config::lport, id, config::tag) < 0) {
		cerr<<drops->why()<<endl;
		return 1;
	}

	dup2(0, 2);

	// wrong format will be detected and thrown away in drops::connect()
	if (boot_node.size() > 0)
		drops->boot_node(boot_node);

	numbers = new (nothrow) Numbers;
	if (!numbers || numbers->init() < 0)
		return 1;

	thread numbers_thread([&]{
		log l; l.init(config::cfgbase + "/" + config::tag + "/numlog.txt");
		for (;;) {
			if (numbers->gen1() < 0)
				l.logit("N", numbers->why());
		}
	});

	drops->loop();

	return 1;
}

