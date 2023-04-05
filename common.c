//
// Created by lauwsj on 3/4/23.
//

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "common.h"

void get_disk_image_mmap(const char *diskimg_path, off_t *size,
                         uint8_t **image) {
    int fd = open(diskimg_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    // get file length
    (*size) = lseek(fd, 0, SEEK_END);
    if ((*size) == -1) {
        perror("lseek");
        exit(EXIT_FAILURE);
    }
    (*image) = mmap(NULL, *size, PROT_READ, MAP_PRIVATE, fd, 0);
    if ((*image) == (void *)-1) {
        close(fd);
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    close(fd);
}

uint32_t convert_sector_to_byte_offset(const struct BPB *hdr,
                                       uint32_t sector_number) {
    return sector_number * hdr->BPB_BytsPerSec;
}

void hexdump(const void *data, size_t size) {
#warning "You must remove this function before submitting."
    FILE *proc;

    proc = popen("hexdump -C", "w");
    if (proc == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }
    fwrite(data, 1, size, proc);
}
