#include <fcntl.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "fat.h"

#define BPB_SIZE sizeof(struct BPB)

void inspect_fat(const char *diskimg_path);

uint32_t get_fat_sector_size(const struct BPB *hdr);

uint32_t get_root_dir_sectors(const struct BPB *hdr);

uint32_t get_data_sectors(const struct BPB *hdr, uint32_t root_dir_sectors, uint32_t fat_size);

uint32_t get_total_sectors(const struct BPB *hdr);

/*
 * Check if the given disk image is a FAT32 disk image.
 * Return true if it is, false otherwise.
 */
int32_t get_fat_version(const char *disk) {
    int fd;
    fd = open(disk, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }

    uint8_t *image = mmap(NULL, BPB_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (image == (void *) -1) {
        perror("mmap");
        exit(1);
    }
    close(fd);

    const struct BPB *hdr = (const struct BPB *) image;

    /*
     * Manual 3.5: Determination of FAT type when mounting the volume
     * The FAT type is determined solely by the count of clusters on the volume (CountOfClusters).
     */
    uint32_t root_dir_sectors = get_root_dir_sectors(hdr);
    uint32_t fat_size, data_sectors, count_of_clusters;
    fat_size = get_fat_sector_size(hdr);
    data_sectors = get_data_sectors(hdr, root_dir_sectors, fat_size);
    count_of_clusters = data_sectors / hdr->BPB_SecPerClus;

    munmap(image, BPB_SIZE);
    if (count_of_clusters < 4085) {
        return 12;
    } else if (count_of_clusters < 65525) {
        return 16;
    } else {
        return 32;
    }
}

uint32_t get_data_sectors(const struct BPB *hdr, uint32_t root_dir_sectors, uint32_t fat_size) {
    uint32_t data_sectors, total_sectors;
    total_sectors = get_total_sectors(hdr);
    data_sectors = total_sectors - (hdr->BPB_RsvdSecCnt + hdr->BPB_NumFATs * fat_size) + root_dir_sectors;
    return data_sectors;
}

uint32_t get_total_sectors(const struct BPB *hdr) {
    uint32_t total_sectors;
    if (hdr->BPB_TotSec16 != 0) {
        total_sectors = hdr->BPB_TotSec16;
    } else {
        total_sectors = hdr->BPB_TotSec32;
    }
    return total_sectors;
}

uint32_t get_root_dir_sectors(const struct BPB *hdr) {
    return ((hdr->BPB_RootEntCnt * 32) + (hdr->BPB_BytsPerSec - 1)) / hdr->BPB_BytsPerSec;
}

uint32_t get_fat_sector_size(const struct BPB *hdr) {
    uint32_t fat_size;
    if (hdr->BPB_FATSz16 != 0) {
        fat_size = hdr->BPB_FATSz16;
    } else {
        fat_size = hdr->fat32.BPB_FATSz32;
    }
    return fat_size;
}

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
