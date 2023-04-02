//
// Created by lauwsj on 3/4/23.
//

#ifndef FAT_INSPECTION_H
#define FAT_INSPECTION_H

#include "fat.h"

#define BPB_SIZE sizeof(struct BPB)

void inspect_fat(const char *diskimg_path);

uint32_t get_fat_version(const char *disk);

uint32_t get_fat_sector_size(const struct BPB *hdr);

uint32_t get_root_dir_sectors(const struct BPB *hdr);

uint32_t get_data_sectors(const struct BPB *hdr, uint32_t root_dir_sectors, uint32_t fat_size);

uint32_t get_total_sectors(const struct BPB *hdr);

#endif //FAT_INSPECTION_H
