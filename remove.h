//
// Created by lauwsj on 3/4/23.
//

#ifndef FAT_REMOVE_H
#define FAT_REMOVE_H

#include <stdbool.h>

void check_absolute_path(const char *path);

int remove_fat(const char *diskimg_path, const char *path);

union DirEntry get_dir_entry_helper(const struct BPB *hdr, FILE *f,
                                    uint32_t max_total_entries,
                                    wchar_t *names[], uint32_t current_index,
                                    uint32_t size);

union DirEntry get_data_dir_one_cluster(const struct BPB *hdr,
                                        uint32_t cluster_number, FILE *f,
                                        wchar_t *names[],
                                        uint32_t current_index, uint32_t size);

uint32_t get_associated_cluster(union DirEntry *dir_entry);

union DirEntry get_dir_entry_on_name(const struct BPB *hdr, wchar_t *names[],
                                     FILE *f, uint32_t current_index,
                                     uint32_t size);

bool is_valid_dir_entry(union DirEntry *result);

union DirEntry createNullDirEntry();

uint32_t get_error_value(const struct BPB *hdr);

void remove_file(const struct BPB *hdr, union DirEntry file_entry, FILE *f);

void remove_fat_entry(const struct BPB *hdr, FILE *f, uint32_t cluster_number,
                      uint32_t *offset, uint32_t *fat_entry_bytes,
                      uint32_t *entry);

union DirEntry embed_offset(FILE *f, union DirEntry *dir_entry);

void mark_entry_unused(union DirEntry *file_entry, FILE *f);

void remove_object(const struct BPB *hdr, union DirEntry dir_entry, FILE *f);

void remove_objects_one_cluster(const struct BPB *hdr, uint32_t cluster_number,
                                FILE *f);

void root_remove(const struct BPB *hdr, FILE *f);

int parse_path(const char *path, wchar_t **name);

#endif // FAT_REMOVE_H