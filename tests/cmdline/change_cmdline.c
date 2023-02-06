#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/prctl.h>
int main(int argc, char *argv[]) {
    int i = 0;
    func(10,argv);
    for(int i = 0;i<100;i++){
    printf("%d",i);
    }
    sleep(10);
}

int func(int i,char *argv[]){
    strcpy(argv[0], "newCMDLINE");
}

