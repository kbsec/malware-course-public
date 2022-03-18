#include "printfile.h"




int main(int argc, char* argv[]){

    if (argc != 4){
        printf("Usage: %s program.exe \"args and args \" outfile.txt\n", argv[0]);
        return 0;
    }
    // arse args
    char* program = argv[1];
    char* args = argv[2];
    char* outfile = argv[3];

    // create buffer for cmdline argument
    // //your solution here!

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    // Prevent dead squirrels 
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    // TODO: Set si.dwFlags...
    // HINT Read this and look for anything that talks about handle inheritance :-)
    //  https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    
    // //your solution here!


    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;

    // TODO: ensure that the child processes can inherit our handles!
    // //your solution here!

    // TODO: Create a file  object and share the handle with a child processes 
    // //your solution here!

    // TODO: Set
    // set startupinfo handles
    // //your solution here!

    
    // Create the child Processes and wait for it to terminate!
    // //your solution here!

    // TODO: perform any cleanup necessary! 
    // The parent processes no longer needs a handle to the child processes, the running thread, or the out file!
    // //your solution here!
    // Finally, print the contents of the file!
    PrintFileContents(outfile);
    return 0;
}