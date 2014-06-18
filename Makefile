TARGETS=banner-grab

all: $(TARGETS)

banner-grab: 
	go build

.PHONY: clean install

install: $(TARGETS)
	echo "Not implemented"	

clean:
	go clean


