all: create_folders build_arpt build_dnst

create_folders:
	mkdir -p bin

build_arpt:
	gcc arpt/main.c -o bin/arpt
	
build_dnst:
	gcc dnst/main.c -o bin/dnst
