//
// Created by lauwsj on 4/4/23.
//

#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>

#include "common.h"
#include "copy_from_image.h"
#include "inspection.h"
#include "list.h"
#include "remove.h"

void copy_from_image(const char *diskimg_path, const char *image_path,
                     const char *local_path) {
    // get or open the local file
    check_local_path_regular_if_exists(local_path);

    FILE *lf = fopen(local_path, "wb");
    if (lf == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    off_t size;
    uint8_t *image;
    get_disk_image_mmap(diskimg_path, &size, &image);
    const struct BPB *hdr = (const struct BPB *)image;

    FILE *f = fopen(diskimg_path, "rb");
    if (f == NULL) {
        fclose(lf);
        munmap(image, size);
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    wchar_t *image_path_names[PATH_MAX];
    int idx_image = parse_path(image_path, image_path_names);

    /*
     * copy the file from the disk image to local
     * 1. Get the dir entry
     * 2. Iterate through all the clusters by iterating the FAT
     * 3. Write each data contained in the cluster to the file
     */
    union DirEntry dir_entry =
        get_dir_entry_on_name(hdr, image_path_names, f, 0, idx_image);
    if (!is_valid_dir_entry(&dir_entry)) {
        munmap(image, size);
        fclose(f);
        perror("Could not locate the exact entry");
        exit(EXIT_FAILURE);
    }
#ifdef DEBUG
    hexdump(&dir_entry, 32);
#endif

    uint32_t error_value = get_error_value(hdr);
    uint32_t size_each_cluster = hdr->BPB_SecPerClus * hdr->BPB_BytsPerSec;
    uint32_t sector_number, offset;
    void *ptr = malloc(size_each_cluster);

    // iterating through all the clusters
    for (uint32_t cluster_number = get_associated_cluster(&dir_entry);
         cluster_number >= 0x2 && cluster_number < error_value;) {
        // get the current cluster
        sector_number = get_data_sector_from_cluster(
            hdr, cluster_number, get_first_data_sector(hdr));
        offset = convert_sector_to_byte_offset(hdr, sector_number);
        fseek(f, offset, SEEK_SET);
        fread(ptr, size_each_cluster, 1, f);

        // write each cluster to the file
        fwrite(ptr, size_each_cluster, 1, lf);

        cluster_number = get_next_cluster(hdr, cluster_number, f);
    }

    for (int i = 0; i < idx_image; i++) {
        free(image_path_names[i]);
    }

    free(ptr);
    munmap(image, size);
    fclose(f);
    fclose(lf);
}

void check_local_path_regular_if_exists(const char *local_path) {
    if (access(local_path, F_OK) == 0) {
        // file exists
        struct stat path_stat;
        stat(local_path, &path_stat);
        bool is_regular_file = S_ISREG(path_stat.st_mode);
        if (!is_regular_file) { // can open the file but not a regular file
            perror("local path doesn't point to a regular file");
            exit(EXIT_FAILURE);
        }
    }
}
