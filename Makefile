all: definitions.pxi
	python setup.py build_ext --inplace

definitions.pxi: generate_defs
	./generate_defs > definitions.pxi

generate_defs:
	cc -Wall -o generate_defs generate_defs.c -lpcap

clean:
	python setup.py clean
	rm -f generate_defs definitions.pxi yappcap.c *.so

install: all
	python setup.py install
.PHONY: clean
.PHONY: install
