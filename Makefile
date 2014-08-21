all: alluvium

alluvium: main.o address.o ipset.o
	$(CXX) $(LDFLAGS) -lskarnet -ls6dns -o $@ $^

%.o: %.cc
	$(CXX) -Wall -c -std=c++11 $(CXXFLAGS) -o $@ $<

install: alluvium
	install -d $(DESTDIR)/usr/sbin/
	install -m 0755 alluvium $(DESTDIR)/usr/sbin/

clean:
	rm -f *~ *.o alluvium
