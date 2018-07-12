# on FreeBSD, this would be c++7 and similar for $LD. Since gcc6 missed define of isascii()
#CXX=c++7

CXX=c++
DEFS=
INC=


#INC+=-I/usr/local/ssl/include
#LIBS+=-L/usr/local/ssl/lib
#LIBS+=-Wl,--rpath=/usr/local/ssl/lib

# LibreSSL setups, define your paths here
#INC+=-I/usr/local/libressl/include
#LIBS+=-L/usr/local/libressl/lib64
#LIBS+=-Wl,--rpath=/usr/local/libressl/lib64
#DEFS+=-DHAVE_LIBRESSL


CXXFLAGS=-O2 -Wall -pedantic -std=c++11 $(INC) $(DEFS)
#LD=c++7
LD=c++
LIBS+=-lssl -lcrypto -pthread


all: clean dropsd


install:
	test -d ~/.drops || (cp -arp ../non-commercial ~/.drops || true)

dropsd: dh.o drops.o peer.o message.o misc.o base64.o ssl.o main.o flavor-linux.o numbers.o missing.o config.o
	$(LD) dh.o drops.o peer.o message.o misc.o base64.o ssl.o main.o flavor-linux.o numbers.o missing.o config.o -o dropsd $(LIBS)

clean:
	rm -rf *.o

dh.o: dh.cc dh2048.cc
	test -s dh2048.cc || ./newdh
	$(CXX) -c $(CXXFLAGS) $<

config.o: config.cc
	$(CXX) -c $(CXXFLAGS) $<

drops.o: drops.cc
	$(CXX) -c $(CXXFLAGS) $<

missing.o: missing.cc
	$(CXX) -c $(CXXFLAGS) -fpermissive $<

numbers.o: numbers.cc
	$(CXX) -c $(CXXFLAGS) $<

peer.o: peer.cc
	$(CXX) -c $(CXXFLAGS) $<

misc.o: misc.cc
	$(CXX) -c $(CXXFLAGS) $<

base64.o: base64.cc
	$(CXX) -c $(CXXFLAGS) $<

message.o: message.cc
	$(CXX) -c $(CXXFLAGS) $<

ssl.o: ssl.cc
	$(CXX) -c $(CXXFLAGS) $<

main.o: main.cc
	$(CXX) -c $(CXXFLAGS) $<

flavor-linux.o: flavor-linux.cc
	$(CXX) -c $(CXXFLAGS) $<

