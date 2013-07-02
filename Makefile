CXX=c++
CFLAGS=-Wall -c -O2 -std=c++0x -pedantic

# actually C++11, but older GCC's do not support c++11
#CFLAGS=-Wall -c -O2 -std=c++11 -pedantic

foo: all

clean:
	rm -f *.o

all: bridge.o wrap.o tuntap.o misc.o main.o dns.o base64.o config.o
	$(CXX) *.o -o fraud-bridge -lcrypto

config.o: config.h config.cc
	$(CXX) $(CFLAGS) config.cc

base64.o: base64.cc base64.h
	$(CXX) $(CFLAGS) base64.cc

dns.o: dns.cc dns.h
	$(CXX) $(CFLAGS) dns.cc

bridge.o: bridge.cc bridge.h
	$(CXX) $(CFLAGS) bridge.cc

wrap.o: wrap.cc wrap.h
	$(CXX) $(CFLAGS) wrap.cc

tuntap.o: tuntap.cc tuntap.h
	$(CXX) $(CFLAGS) tuntap.cc

misc.o: misc.cc misc.h
	$(CXX) $(CFLAGS) misc.cc

main.o: main.cc
	$(CXX) $(CFLAGS) main.cc

