all: dnsinject dnsdetect

dnsinject: dnsinject.c 
	gcc dnsinject.c -o dnsinject -lpthread -lssl -lcrypto -lpcap -lnet -lresolv

dnsdetect: dnsdetect.c
	gcc dnsdetect.c -o dnsdetect -lpthread -lssl -lcrypto -lpcap -lnet -lresolv

clean:
	rm -f dnsinject dnsdetect
