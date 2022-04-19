CC=gcc 
CXX=g++
CFLAGS=-municode -std=c++11
LDFLAGS=-lWinmm
DLL=-shared

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else
	RM=rm
endif


all: surprise.dll testDll


surprise.res:
	windres surprise.rc -O coff -o  surprise.res

surprise.dll: surprise.res	
	$(CXX)  surprise.cpp surprise.res  $(DLL) $(CFLAGS) $(LDFLAGS) -o surprise.dll

testDll:
	$(CXX) test_dll.cpp -o testDll.exe

clean:
	$(RM) *.exe
	$(RM) *.dll
	$(RM) *.res