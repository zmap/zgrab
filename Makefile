TARGETS := zgrab

all: $(TARGETS)

zgrab: *.go
	go build

.PHONY: clean install uninstall zgrab

install: $(TARGETS)
	install -m 755 $(TARGETS) /usr/local/bin

uninstall:
	rm -f $(addprefix /usr/local/bin/, $(TARGETS))

clean:
	go clean

