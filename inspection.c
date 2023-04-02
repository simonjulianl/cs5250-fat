//
// Created by lauwsj on 3/4/23.
//
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "inspection.h"

/*
 * Check if the given disk image is a FAT32 disk image.
 * Return true if it is, false otherwise.
 */
uint32_t get_fat_version(const char *disk) {
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
