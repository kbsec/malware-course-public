CC=gcc
CXX=g++


ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

all: base64.exe aestest.exe http.exe 

.PHONY: all clean 

base64.exe:
	$(CXX) base64/base64.cpp  -lCrypt32   -o bin/base64.exe 

aestest.exe:
	$(CXX) aesgcm/aesgcm.cpp  aesgcm/test_aesgcm.cpp  -lcrypt32 -lbcrypt -o bin/aesgcm.exe



http.exe:
	$(CXX) http/http.cpp -lwinhttp  -o bin/http.exe


submission.zip:
	echo "[+] Making submission. Make sure you have all of your Makefiles and src code!"
	zip -r submission.zip base64 http aesgcm 

clean:
	$(RM)  bin/*.exe 
 	$(RM) submission.zip