all: build_arpt

build_arpt:
	gcc arpt/main.c -o ../bin/arpt
