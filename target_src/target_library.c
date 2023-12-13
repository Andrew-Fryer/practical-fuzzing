#include <stdio.h>


int parse_file(char* path) {
    int size = 1024;
    char buf[size];
    int hasA = 0;
    int hasB = 0;
    int hasC = 0;
    FILE* f = fopen(path, "r");
    if(!f) {
        fprintf(stderr, "Failed to open file: %s\n", path);
        return 1;
    }
    fread(buf, size, 1, f);
    for(int i = 0; i < size && buf[i]; i++) {
        if(buf[i] == 'A') {
            hasA = 1;
        } else if(buf[i] == 'B') {
            hasB = 1;
        } else if(buf[i] == 'C') {
            hasC = 1;
        } else if(hasA && hasB && hasC) {
            // this might crash!
            printf("Discovered interesting value: %x\n", buf[(int)buf[i] * (int)buf[i] * (int)buf[i] * (int)buf[i]]);
            return 0;
        }
    }
    fclose(f);
    printf("done parsing file\n");
    return 0;
}
