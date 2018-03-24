PREFIX := /usr/local

CC      := gcc
CFLAGS  += -I$(CPATH) -O1 -fPIC -Wall -Wextra \
	   -Wno-unused-parameter -Wno-unused-function
LDLIBS  := -lcrypto -lssl
PROGS   := sha_lext_attack

all: $(PROGS)

install:
	$(foreach prog, $(PROGS), \
		install -m 755 $(prog) $(PREFIX)/bin/$(prog))

clean:
	rm -f *.o $(PROGS)

.DEFAULT_GOAL := all
.PHONY: all
