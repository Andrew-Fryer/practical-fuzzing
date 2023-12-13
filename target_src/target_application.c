#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <target_library.h>


int spooky_license_global[10];
int license_check(int arr[], int mode) { // todo: use arr and mode somehow
    unsigned long tmp = (unsigned long)time(NULL);
    return ((unsigned long)(spooky_license_global[0] ^ 0xDEADBEEF)) < tmp
        && spooky_license_global[3] == (spooky_license_global[0] * (spooky_license_global[1] ^ spooky_license_global[2]))
        && spooky_license_global[4] == 153
        && spooky_license_global[5] == (spooky_license_global[3] ^ spooky_license_global[4] ^ (int)license_check);
        // && (spooky_license_global[0] = (0xDEADBEEF ^ tmp)); // if I do this, I need to update the dependent elements of spooky_license_check too
}

int print_help() {
    if(!license_check(spooky_license_global, 0)) {
        exit(1);
    }
    printf("Please enter '1' or '2':\n");
    printf("('1' is for inputting a file)\n");
    printf("('2' is for exitting)\n");
    return 0;
}

int get_line(char* buf, int size) {
    int ret = read(0, buf, size);
    if(ret < 0) {
        fprintf(stderr, "failed to read from stdin\n");
        exit(1);
    }
    buf[ret] = '\0';
    printf("read: %s\n", buf);
    if(buf[ret - 1] != '\n') {
        fprintf(stderr, "expected newline at end of stdin line, but got: %x\n", buf[ret - 1]);
        exit(1);
    }
    buf[ret - 1] = '\0'; // overwrite NL with NULL
    return 0;
}

int main(int argc, char* argv[]) {
    memset(spooky_license_global, 0xDEADBEEF, sizeof spooky_license_global);
    if(argc == 2 && strcmp(argv[1], "-l") == 0) {
        // spooky code that would be more complex (wacky computation of indirect jumps and such) in reality
        unsigned long tmp = (unsigned long)time(NULL);
        spooky_license_global[0] ^= tmp;
        spooky_license_global[3] = spooky_license_global[0] * (spooky_license_global[1] ^ spooky_license_global[2]);
        spooky_license_global[4] = argv[1][0] + argv[1][1];
        spooky_license_global[5] = spooky_license_global[3] ^ spooky_license_global[4] ^ (int)license_check;
    } else if(argc > 1) {
        printf("Usage: ./target_application [-l]\n");
        return 1;
    }
    int size = 1024;
    char buf[size];

    print_help();
    while(1) {
        if(!license_check(spooky_license_global, 1)) {
            exit(1);
        }
        fflush(stdout); // this is helpful when stdout is piped
        get_line(buf, size);
        if(strcmp(buf, "1") == 0) {
            printf("Please enter the file's path:\n");
            fflush(stdout);
            get_line(buf, size);
            if(!license_check(spooky_license_global, 2)) {
                exit(1);
            }
            parse_file(buf);
        } else if(strcmp(buf, "2") == 0) {
            return 0;
        } else {
            print_help();
        }
    }
    return 0;
}
