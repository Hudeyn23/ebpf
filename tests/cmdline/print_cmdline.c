#include <stdio.h>
#include <fcntl.h>
#include <string.h>
int main(int argc, char *argv[]) {
    int i = 0;
    printf("%s",argv[1]);
    for(int i = 0;i<5;i++){
    printf("%d",i);
    }
    return 0;
}
