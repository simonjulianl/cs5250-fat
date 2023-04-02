#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "inspection.h"
#include "list.h"


int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);
    if (argc < 3) {
        fprintf(stderr, "Usage: %s disk.img <ck|ls> \n", argv[0]);
        exit(1);
    }
    const char *diskimg_path = argv[1];
    const char *op = argv[2];

    if (strcmp(op, "ck") == 0) {
        inspect_fat(diskimg_path);
    } else if (strcmp(op, "ls") == 0) {
        list_fat(diskimg_path);
    } else {

    }
}

