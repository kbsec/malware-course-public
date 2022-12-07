#include <stdio.h>


int main(){
    auto x = "Hello there!";
    char y[20];
    int z = 13;
    // memcpy (y, x, 13);
    for(int i = 0; i < z; i++){

        //*(y + i) = *( x + i);
        y[i] = x[i];
    }
    printf("%s\n", x);


}