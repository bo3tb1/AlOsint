GOOSE ?= goose

.PHONY: all clean test install uninstall

all: alosint

alosint: alosint.goose
	$(GOOSE) build alosint.goose --cc gcc -o alosint

clean:
	rm -f alosint *.o

test:
	$(GOOSE) check alosint.goose
	cd tests && ./run.sh

install: alosint
	install -m 755 alosint /usr/local/bin/alosint

uninstall:
	rm -f /usr/local/bin/alosint
