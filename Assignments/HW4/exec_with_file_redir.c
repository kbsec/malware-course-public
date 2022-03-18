#include "printfile.h"




int main(int argc, char* argv[]){

    if (argc != 4){
        printf("Usage: %s program.exe \"args and args \" outfile.txt\n", argv[0]);
        return 0;
    }
    char* program = argv[1];
    char* args = argv[2];
    char* outfile = argv[3];

    // TODO: Make cmd line from program, args, and outfile
    // //your solution here!

    // Values needed for CreateProcessA
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    // Dead squirrels
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    // Dead squirrels 
    ZeroMemory(&pi, sizeof(pi));

    // //your solution here!

    // TODO: Wait for processes to exit 
    // //your solution here!

    // TODO: Cleanup
    // //your solution here!
    
    PrintFileContents(outfile);
    return 0;
}