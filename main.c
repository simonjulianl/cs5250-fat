#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "copy_from_image.h"
#include "copy_from_local.h"
#include "inspection.h"
#include "list.h"
#include "remove.h"

#define IMAGE_PREFIX "image:"
#define LOCAL_PREFIX "local:"

bool starts_with(const char *pre, const char *str) {
    size_t len_prefix = strlen(pre), len_string = strlen(str);
    return len_string < len_prefix ? false : memcmp(pre, str, len_prefix) == 0;
}

int main(int argc, char *argv[]) {
    setbuf(stdout, NULL); // unbuffer the stream, immediately output it
    if (argc < 3) {
        fprintf(stderr, "Usage: %s disk.img <ck|ls|rm|cp> [path1] [path2]\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *diskimg_path = argv[1];
    if (access(diskimg_path, F_OK) != 0) {
        fprintf(stderr, "Unable to locate disk image");
        exit(EXIT_FAILURE);
    }
    const char *op = argv[2];

    if (strcmp(op, "ck") == 0) {
        inspect_fat(diskimg_path);
    } else if (strcmp(op, "ls") == 0) {
        list_fat(diskimg_path);
    } else if (strcmp(op, "rm") == 0) {
        remove_fat(diskimg_path, argv[3]);
    } else if (strcmp(op, "cp") == 0) { // copy
        const char *first_path = argv[3];
        const char *second_path = argv[4];
        if (starts_with(IMAGE_PREFIX, first_path) &&
            starts_with(LOCAL_PREFIX, second_path)) {
            first_path += strlen(IMAGE_PREFIX);
            second_path += strlen(LOCAL_PREFIX);
            copy_from_image(diskimg_path, first_path, second_path);
        } else if (starts_with(LOCAL_PREFIX, first_path) &&
                   starts_with(IMAGE_PREFIX, second_path)) {
            first_path += strlen(LOCAL_PREFIX);
            second_path += strlen(IMAGE_PREFIX);
            copy_from_local(diskimg_path, first_path, second_path);
        } else {
            goto error;
        }
    } else {
    error:
        fprintf(stderr, "Unknown command, please check the usage");
        exit(EXIT_FAILURE);
    }
}
