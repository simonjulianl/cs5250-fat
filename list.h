//
// Created by lauwsj on 3/4/23.
//

#ifndef FAT_LIST_H
#define FAT_LIST_H

#define ENTRY_SIZE_BYTES 32
#define LAST_LONG_ENTRY 0x40

#include "fat.h"
#include <stdbool.h>

void list_fat(const char *diskimg_path);

uint32_t get_sector_from_cluster(const struct BPB *hdr, uint32_t N, uint32_t first_data_sector);

void populate_directory_name(union DirEntry *dir_entry, wchar_t *directory_name);

bool isLastLongName(uint8_t ordinal_value);

wchar_t combine_bytes(uint8_t high_byte, uint8_t low_byte);

void list_data_dir_one_cluster(const struct BPB *hdr, uint32_t cluster_number, FILE *f, wchar_t *prefix);

uint32_t get_entries_per_cluster(const struct BPB *hdr);

uint32_t get_next_cluster(const struct BPB *hdr, uint32_t cluster_number, FILE *f);

void list_data_dir(const struct BPB *hdr, uint32_t cluster_number, FILE *f, wchar_t *prefix);

void list_root_dir(const struct BPB *hdr, FILE *f);

void read_dir_helper(const struct BPB *hdr, FILE *f, uint32_t max_total_entries, wchar_t *prefix);

bool is_excluded_dir(union DirEntry *dir_entry);

void
get_offset_given_cluster(const struct BPB *hdr, uint32_t cluster_number, uint32_t *fat_entry_bytes, uint32_t *offset);

#endif //FAT_LIST_H
