#include <stdio.h>
#include <time.h>
#include <unistd.h>



int count = 0;
int main() {

while(1)
{
    count++;

    printf("Tick Tock -- Cycle %d  \n", count );  
    usleep(1000000);

}

}
