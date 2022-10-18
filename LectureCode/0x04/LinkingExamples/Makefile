
all: hellozig hellogpp hellosigdebug 
hellozig:
	zig c++ helloworld.cpp -o helloworld_zig.exe

hellogpp:
	g++ helloworld.cpp -o helloworld_gpp.exe

hellozigdebug:
	zig c++ -g helloworld.cpp -o helloworld_debug.exe
hello:
	hellozig hellogpp


