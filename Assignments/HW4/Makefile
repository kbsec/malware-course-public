CC=gcc
CXX=g++
ifeq ($(OS),Windows_NT)
    RM = powershell /c rm
else
    RM = rm -f
    RRM = rm -f -r
endif

LDFLAGS=-lBcrypt -lWinmm

.PHONY: clean
STRIP=-s

all: exec_with_file_redir exec_with_file exec_with_pipe

test_all: test_exec_with_file_redir test_exec_with_file test_exec_with_pipe

exec_with_file_redir:
	$(CC) exec_with_file_redir.c -o bin/exec_with_file_redir.exe

test_exec_with_file_redir:
	bin/exec_with_file_redir.exe "whoami /priv" " " "test.txt"
	bin/exec_with_file_redir.exe "whoami" " " "test.txt"
	bin/exec_with_file_redir.exe "ping.exe" "127.0.0.1" "test.txt"

exec_with_file:
	$(CC) exec_with_file.c -o bin/exec_with_file.exe

test_exec_with_file:exec_with_file
	bin/exec_with_file.exe "whoami /priv" " " "test.txt"
	bin/exec_with_file.exe "whoami" " " "test.txt"
	bin/exec_with_file.exe "ping.exe" "127.0.0.1" "test.txt"

exec_with_pipe:
	$(CC) exec_with_pipe -o bin/exec_with_pipe.exe

test_exec_with_pipe:exec_with_pipe
	bin/exec_with_pipe.exe "whoami /priv" " "
	bin/exec_with_pipe.exe "whoami" " " 
	bin/exec_with_pipe.exe "ping.exe" "127.0.0.1" 
