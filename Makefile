CXX=c++

SSL=
#SSL=/opt/ssl/libressl-3.6.1

INC=-I$(SSL)/include
LIBS=-lcrypto -Wl,--rpath=$(SSL)/lib64

CXXFLAGS=-Wall -c -O2 -std=c++11 -pedantic $(INC)

.PHONY: all clean

all: bridge.o wrap.o tuntap.o misc.o main.o dns.o base64.o config.o
	$(CXX) *.o -o fraud-bridge $(LIBS)

config.o: config.h config.cc
	$(CXX) $(CXXFLAGS) config.cc

base64.o: base64.cc base64.h
	$(CXX) $(CXXFLAGS) base64.cc

dns.o: dns.cc dns.h
	$(CXX) $(CXXFLAGS) dns.cc

bridge.o: bridge.cc bridge.h
	$(CXX) $(CXXFLAGS) bridge.cc

wrap.o: wrap.cc wrap.h
	$(CXX) $(CXXFLAGS) wrap.cc

tuntap.o: tuntap.cc tuntap.h
	$(CXX) $(CXXFLAGS) tuntap.cc

misc.o: misc.cc misc.h
	$(CXX) $(CXXFLAGS) misc.cc

main.o: main.cc
	$(CXX) $(CXXFLAGS) main.cc

clean:
	rm -f *.o


