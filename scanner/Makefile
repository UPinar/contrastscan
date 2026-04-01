CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lcurl -lssl -lcrypto -lresolv -lcjson

all: contrastscan

contrastscan: src/contrastscan.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# unit tests
test: tests/test_scoring.c
	$(CC) $(CFLAGS) -o test_scoring $< -lcjson
	./test_scoring

# integration tests (requires network + jq)
test-integration: contrastscan
	bash tests/test_integration.sh

# standalone modules (development/debug)
headers: src/headers.c
	$(CC) $(CFLAGS) -o $@ $< -lcurl -lcjson

ssl_check: src/ssl_check.c
	$(CC) $(CFLAGS) -o $@ $< -lssl -lcrypto -lcjson

dns_check: src/dns_check.c
	$(CC) $(CFLAGS) -o $@ $< -lresolv -lcjson

clean:
	rm -f contrastscan headers ssl_check dns_check test_scoring

.PHONY: all test test-integration clean
