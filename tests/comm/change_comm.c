#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/prctl.h>
int main(int argc, char *argv[]) {
    int i = 0;
    prctl(PR_SET_NAME, "newComm");
    for(int i = 0;i<5;i++){
    printf("%d",i);
    }
    return 0;
}