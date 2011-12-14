all: yappcap.c
	python setup.py build_ext

yappcap.c: yappcap.pyx definitions.pxi
	cython yappcap.pyx

definitions.pxi: generate_defs
	./generate_defs > definitions.pxi

generate_defs:
	cc -Wall -o generate_defs generate_defs.c -lpcap

clean:
	python setup.py clean
	rm -f generate_defs definitions.pxi *.so

regen: clean
	rm -f yappcap.c
	make

install: all
	python setup.py install

.PHONY: clean
.PHONY: install
