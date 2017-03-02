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

#ifndef drops_misc_h
#define drops_misc_h

#include <cstdio>
#include <sys/time.h>
#include <string>


namespace drops {


namespace timeouts {

enum {
	// for connected/learned nodes re-connect timers
	none		= 0,
	initial		= 1,
	reconnect	= 30,
	fin_wait	= 180,

	// for state machine timeouts
	connect		= 5,
	pingpong	= 30,
	sleeping	= 5
};


}


enum {
	one_day		= 24*60*60,
	seven_days	= 7*one_day,
	ten_days	= 10*one_day,
	twelve_days	= 12*one_day,
	two_weeks	= 14*one_day
};


std::string &blob2hexhash(const std::string &, std::string &);

std::string &blob2hexid(const std::string &, std::string &);

std::string &blob2hex(const std::string &, std::string &);

bool is_hex_hash(const std::string &);

bool is_valid_have(const std::string &);

extern unsigned int max_msg_size;

}

#endif
