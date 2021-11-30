LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o ethhdr.o ip.o iphdr.o mac.o tcphdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ 

clean:
	rm -f tcp-block *.o