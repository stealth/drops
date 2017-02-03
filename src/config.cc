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

#include <cstdint>
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include "message.h"
#include "config.h"


using namespace std;

namespace drops {

namespace config {


string cfgbase = "";

string laddr = "0.0.0.0";
string  lport = "7350";
string laddr6 = "::";
string  lport6 = "7350";

string tag = "global";

uint64_t max_cache_size = 1000*1024*1024;

msg_filter filter;

}


int parse_config(const string &cfgbase)
{
	ifstream fin{cfgbase + "/config", ios::in};
	if (!fin)
		return -1;

	string sline = "";

	for (;;) {
		getline(fin, sline, '\n');
		if (!fin.good())
			break;

		sline.erase(remove(sline.begin(), sline.end(), ' '), sline.end());
		sline.erase(remove(sline.begin(), sline.end(), '\t'), sline.end());

		if (sline.find("max_cache=") == 0)
			config::max_cache_size = (uint64_t)strtoull(sline.c_str() + 10, nullptr, 10)*1024*1024;
		else if (sline.find("laddr=") == 0)
			config::laddr = sline.substr(6);
		else if (sline.find("lport=") == 0)
			config::lport = sline.substr(6);
		else if (sline.find("laddr6=") == 0)
			config::laddr6 = sline.substr(7);
		else if (sline.find("lport6=") == 0)
			config::lport6 = sline.substr(7);
		else if (sline.find("filter=") == 0) {
			string::size_type comma = sline.find(",");
			if (comma == string::npos)
				continue;
			config::filter.add_filter(sline.substr(7, comma - 7), sline.substr(comma + 1));
		}
	}

	return 0;
}


}

