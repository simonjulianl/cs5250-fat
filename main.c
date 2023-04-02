#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "inspection.h"


/*
 * Hexdump the given data.
 *
 * WARNING: THIS FUNCTION IS ONLY FOR DEBUGGING PURPOSES!
 * This function prints the data using an external command called "hexdump", but
 * your program should not depend on external programs. Before submitting, you
 * must remove this function. If you include this function in your submission,
 * you may face a penalty.
 */
void hexdump(const void *data, size_t size) {
#warning "You must remove this function before submitting."
    FILE *proc;

    proc = popen("hexdump -C", "w");
    if (proc == NULL) {
        perror("popen");
        exit(1);
    }
    fwrite(data, 1, size, proc);
}

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
    } else {

    }
}

void inspect_fat(const char *diskimg_path) {
    int fd = open(diskimg_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    // get file length
    off_t size = lseek(fd, 0, SEEK_END);
    if (size == -1) {
        perror("lseek");
        exit(1);
    }
    uint8_t *image = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (image == (void *) -1) {
        perror("mmap");
        exit(1);
    }
    close(fd);

    /*
     * Print some information about the disk image.
     */
    const struct BPB *hdr = (const struct BPB *) image;
    uint32_t fat_size = get_fat_sector_size(hdr);
    uint32_t root_dir_sectors = get_root_dir_sectors(hdr);

    printf("FAT%d filesystem\n", get_fat_version(diskimg_path));
    printf("BytsPerSec = %u\n", hdr->BPB_BytsPerSec);
    printf("SecPerClus = %u\n", hdr->BPB_SecPerClus);
    printf("RsvdSecCnt = %u\n", hdr->BPB_RsvdSecCnt);
    printf("FATsSecCnt = %u\n", hdr->BPB_NumFATs * fat_size);
    printf("RootSecCnt = %u\n", root_dir_sectors);
    printf("DataSecCnt = %u\n", get_data_sectors(hdr, root_dir_sectors, fat_size));

    munmap(image, size);
}
