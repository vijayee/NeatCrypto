OPENSSLPATH =/usr/local/lib64/libcrypto.a
build:
	mkdir -p build
	mkdir -p build/lib
	mkdir -p build/test
libneat: build
	clang -o build/lib/neat.o -c NeatCrypto/c/neat.c -I/home/victor/.local/share/ponyup/ponyc-release-0.48.0-x86_64-linux-gnu/include
	cd build/lib && ar -x  $(OPENSSLPATH)
	ar rcs build/lib/libneat.a build/lib/*.o
	rm build/lib/*.o
install: libneat
	mkdir -p /usr/local/lib/NeatCrypto
	cp build/lib/libneat.a /usr/local/lib/NeatCrypto
test: libneat
	ponyc NeatCrypto/test -o build/test --debug -p build/lib
	./build/test/test
