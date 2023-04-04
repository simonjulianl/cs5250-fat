//
// Created by lauwsj on 4/4/23.
//

#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <wchar.h>

#include "common.h"
#include "copy_from_image.h"
#include "copy_from_local.h"
#include "inspection.h"
#include "list.h"
#include "remove.h"

void write_local_to_image(FILE *lf, const struct BPB *hdr, FILE *f,
                          union DirEntry *dir_entry);

void mark_fat_file_as_free(const struct BPB *hdr, FILE *f,
                           union DirEntry *file_entry);

void update_fat_entry(const struct BPB *hdr, FILE *f, uint32_t cluster_required,
                      const uint32_t *fat_entries, uint32_t fat_starting_offset,
                      uint32_t next_cluster_index, uint32_t fat_offset_bytes,
                      uint32_t *entry);
void update_dir_entry_fat(FILE *f, const union DirEntry *file_entry,
                          uint32_t fat_entry);
void copy_from_local(const char *diskimg_path, const char *local_path,
                     const char *image_path) {
    // get or open the lo
    check_local_path_regular_if_exists(local_path);

    char str[2] = "\0";
    str[0] = image_path[strlen(image_path) - 1];
    if (strcmp("/", image_path) == 0 || strcmp("/", str) == 0) {
        // either its only root or its a dir
        perror("Invalid image path");
        exit(EXIT_FAILURE);
    }

    FILE *lf = fopen(local_path, "rb");
    if (lf == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    off_t size;
    uint8_t *image;
    get_disk_image_mmap(diskimg_path, &size, &image);
    const struct BPB *hdr = (const struct BPB *)image;

    /**
     * By default, mkfs.fat doesn't create the FSInfo
     * Therefore, in general we shouldn't rely on FSInfo as the docs also
     * mention that the structure is advisory only and it only helps to optimize
     * the driver
     */

    FILE *f = fopen(diskimg_path, "rb+");
    if (f == NULL) {
        fclose(lf);
        munmap(image, size);
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    wchar_t *image_path_names[PATH_MAX];
    int idx_image = parse_path(image_path, image_path_names);

    union DirEntry dir_entry =
        get_dir_entry_on_name(hdr, image_path_names, f, 0, idx_image);
    if (is_valid_dir_entry(&dir_entry)) {
        mark_fat_file_as_free(hdr, f, &dir_entry);
        dir_entry =
            get_dir_entry_on_name(hdr, image_path_names, f, 0, idx_image);
        write_local_to_image(lf, hdr, f, &dir_entry);
#ifdef DEBUG
        dir_entry =
            get_dir_entry_on_name(hdr, image_path_names, f, 0, idx_image);
        hexdump(&dir_entry, 32);
#endif
    } else {
        // TODO: create the long file name entry and put it in the
        // the directory if it exists, otherwise returns error
    }

    for (int i = 0; i < idx_image; i++) {
        free(image_path_names[i]);
    }

    munmap(image, size);
    fclose(f);
    fclose(lf);
}

void write_local_to_image(FILE *lf, const struct BPB *hdr, FILE *f,
                          union DirEntry *dir_entry) {

    fseek(lf, 0, SEEK_SET);
    fseek(lf, 0, SEEK_END);
    off_t file_size = ftell(lf);
    fseek(lf, 0, SEEK_SET);
    if (file_size == 0) {
        // do not need to write anything
        return;
    }

    uint32_t bytes_written = 0; // max file size in FAT32 is 2^32 - 1 bytes
    uint32_t size_each_cluster = hdr->BPB_SecPerClus * hdr->BPB_BytsPerSec;

    // account for EOF and ceil it
    uint32_t cluster_required =
        (file_size + size_each_cluster - 1) / size_each_cluster + 1;

    uint32_t fat_entries[cluster_required];
    uint32_t fat_starting_offset = hdr->BPB_BytsPerSec * hdr->BPB_RsvdSecCnt;

    // end of cluster can be indicated using OR mask 0x0FFFFFFF
    uint32_t counter = 0;
    uint32_t total_entry_fat =
        hdr->fat32.BPB_FATSz32 * hdr->BPB_BytsPerSec / ENTRY_SIZE_BYTES;

    for (uint32_t i = hdr->fat32.BPB_RootClus + 1;
         counter < cluster_required && i < total_entry_fat; i++) {
        // seek the cluster
        uint32_t *fat_entry = malloc(32);
        fseek(f, fat_starting_offset + i * ENTRY_SIZE_BYTES, SEEK_SET);
        fread(fat_entry, ENTRY_SIZE_BYTES, 1, f);
        if ((*fat_entry & 0x0FFFFFFF) == 0x00000000) {
            fat_entries[counter++] = i; // ith fat entry
        }
        free(fat_entry);
    }

    if (counter < cluster_required) {
        perror("Not enough space in the image, maybe due to internal "
               "fragmentation");
        exit(EXIT_FAILURE);
    }

    // one way to chain, for each entry, just chain them in the order of fat
    // entries
    void *ptr = malloc(size_each_cluster);
    fseek(lf, 0, SEEK_SET); // defensive programming
    uint32_t current_cluster_index = 0;

    while (bytes_written < file_size) {
        // read the file
        fread(ptr, size_each_cluster, 1, lf);
        // write to the cluster
        uint32_t next_cluster_index = current_cluster_index + 1;
        uint32_t fat_offset_bytes = fat_entries[current_cluster_index] * 4;
        uint32_t sector =
            get_sector_from_cluster(hdr, fat_entries[current_cluster_index],
                                    get_first_data_sector(hdr));
        uint32_t sector_offset = sector * hdr->BPB_BytsPerSec;

        fseek(f, sector_offset, SEEK_SET);
        fwrite(ptr, size_each_cluster, 1, f);

        // write to the fat
        uint32_t *entry = malloc(32);
        update_fat_entry(hdr, f, cluster_required, fat_entries,
                         fat_starting_offset, next_cluster_index,
                         fat_offset_bytes, entry);
        free(entry);
        bytes_written += size_each_cluster; // may be less for last cluster
        current_cluster_index = next_cluster_index;
    }
    free(ptr);
    // update the current dir offset to point to the first FAT
    update_dir_entry_fat(f, dir_entry, fat_entries[0]);
}

void update_fat_entry(const struct BPB *hdr, FILE *f, uint32_t cluster_required,
                      const uint32_t *fat_entries, uint32_t fat_starting_offset,
                      uint32_t next_cluster_index, uint32_t fat_offset_bytes,
                      uint32_t *entry) {
    for (int i = 0; i < hdr->BPB_NumFATs; i++) {
        uint32_t fat_table_copy_offset =
            hdr->fat32.BPB_FATSz32 * hdr->BPB_BytsPerSec * i +
            fat_starting_offset + fat_offset_bytes;
        fseek(f, fat_table_copy_offset, SEEK_SET);
        fread(entry, 4, 1, f);
        (*entry) &= 0xF0000000;
        if (next_cluster_index == cluster_required - 1) {
            // last cluster
            (*entry) |= 0x0FFFFFFF;
        } else {
            (*entry) |= fat_entries[next_cluster_index];
        }
        fseek(f, fat_table_copy_offset, SEEK_SET);
        fwrite(entry, 4, 1, f);
    }
}

void mark_fat_file_as_free(const struct BPB *hdr, FILE *f,
                           union DirEntry *file_entry) {
    uint32_t error_value = get_error_value(hdr);
    uint32_t cluster_number, offset, fat_entry_bytes;
    uint32_t entry, next_cluster;
    for (cluster_number = get_associated_cluster(file_entry);
         cluster_number > 0x2 && cluster_number < error_value;) {
        next_cluster = get_next_cluster(hdr, cluster_number, f);
        remove_fat_entry(hdr, f, cluster_number, &offset, &fat_entry_bytes,
                         &entry);
        cluster_number = next_cluster;
    }

    // change EOF to also free list
    remove_fat_entry(hdr, f, cluster_number, &offset, &fat_entry_bytes, &entry);

    // mark the cluster associated with this entry to be 0
    update_dir_entry_fat(f, file_entry, 0x00000000);

    // Note: assuming that the CrtTime and WrtTime
    // should be updated by the driver, not this CLI tool
    // Therefore those values won't be updated here
}

void update_dir_entry_fat(FILE *f, const union DirEntry *file_entry,
                          uint32_t fat_entry) {
    uint32_t hi_offset = file_entry->dir.OFFSET + 20;
    uint32_t low_offset = file_entry->dir.OFFSET + 26;

    uint16_t upper_value = fat_entry >> 16;
    uint16_t lower_value = fat_entry & 0xFFFF;
    fseek(f, hi_offset, SEEK_SET);
    fwrite(&upper_value, 2, 1, f);
    fseek(f, low_offset, SEEK_SET);
    fwrite(&lower_value, 2, 1, f);
}
