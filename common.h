//
// Created by lauwsj on 3/4/23.
//

#ifndef FAT_COMMON_H
#define FAT_COMMON_H

#include "fat.h"

void get_disk_image_mmap(const char *diskimg_path, off_t *size,
                         uint8_t **image);

uint32_t convert_sector_to_byte_offset(const struct BPB *hdr,
                                       uint32_t sector_number);

void hexdump(const void *data, size_t size);

#endif // FAT_COMMON_H
