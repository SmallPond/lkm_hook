.PHONY : module demo  clean all

all: module demo 

module:
	cd module && $(MAKE) -f Makefile all
demo: c_api
	cd "demo/go/src" && go build main.go packet_hook.go

c_api:
	cd api && $(MAKE) -f Makefile all
install:
	cd module && $(MAKE) -f Makefile install

remove:
	cd module && $(MAKE) -f Makefile remove	

run:
	cd "demo/go/src" && sudo ./main
	
clean:
	cd module && $(MAKE) -f Makefile clean
	cd api && $(MAKE) -f Makefile clean
	cd "demo/go/src" && go clean

