all: alluvium

alluvium: main.o address.o ipset.o
	$(CXX) $(LDFLAGS) -lskarnet -ls6dns -o $@ $^

%.o: %.cc
	$(CXX) -Wall -c -std=c++11 $(CXXFLAGS) -o $@ $<

clean:
	rm -f *~ *.o alluvium
