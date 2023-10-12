OBJECTS := scan.o hidden_files.o hidden_ports.o hidden_procs.o injected_libraries.o misc_checks.o fuzzy.o edit_dist.o
PWD := $(shell pwd)
HEADERS := $(PWD)/include

all:
	gcc -fPIC -I $(HEADERS) -c src/*.c
	gcc -fPIC $(OBJECTS) -o scan

clean:
	rm -rf *.o scan