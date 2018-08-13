all : arp_spoof

arp_spoof: arp_spoof.o
	g++ -g -o arp_spoof arp_spoof.o -lpcap

arp_spoof.o:
	g++ -g -c -o arp_spoof.o main.cpp

clean:
	rm -f arp_spoof
	rm -f *.o

