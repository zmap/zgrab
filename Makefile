TARGETS := banner-grab

all: $(TARGETS)

banner-grab: *.go
	go build

.PHONY: clean install uninstall banner-grab

install: $(TARGETS)
	install -m 755 $(TARGETS) /usr/local/bin

uninstall:
	rm -f $(addprefix /usr/local/bin/, $(TARGETS))

clean:
	go clean

