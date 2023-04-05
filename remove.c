//
// Created by lauwsj on 3/4/23.
//

#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <wchar.h>

#include "common.h"
#include "inspection.h"
#include "list.h"
#include "remove.h"

int remove_fat(const char *diskimg_path, const char *path) {
    if (path != NULL && path[0] != '/') {
        perror("Invalid absolute path");
        exit(EXIT_FAILURE);
    }

    off_t size;
    uint8_t *image;
    get_disk_image_mmap(diskimg_path, &size, &image);
    const struct BPB *hdr = (const struct BPB *)image;

    FILE *f = fopen(diskimg_path, "rb+");
    if (f == NULL) {
        munmap(image, size);
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    bool is_root = false;
    if (strcmp("/", path) == 0) {
        is_root = true;
    }

    if (!is_root) {
        wchar_t *name[PATH_MAX];
        int idx = parse_path(path, name);

        union DirEntry dir_entry = get_dir_entry_on_name(hdr, name, f, 0, idx);
        if (!is_valid_dir_entry(&dir_entry)) {
            fclose(f);
            munmap(image, size);
            perror("Could not locate the exact entry");
            exit(EXIT_FAILURE);
        }

        remove_object(hdr, dir_entry, f);
        for (int i = 0; i < idx; i++) {
            free(name[i]);
        }
    } else {
        root_remove(hdr, f);
    }

    fclose(f);
    munmap(image, size);
    return 0;
}

int parse_path(const char *path, wchar_t **name) {
    char *token = strtok((char *)path, "/");
    int idx = 0;

    while (token != NULL) {
        wchar_t temp[PATH_MAX];
        mbstowcs(temp, token, PATH_MAX);
        wchar_t *temp_pointer = malloc(PATH_MAX);
        wcpcpy(temp_pointer, temp);
        name[idx++] = temp_pointer;
        token = strtok(NULL, "/");
    }
    return idx;
}

union DirEntry get_data_dir(const struct BPB *hdr, uint32_t cluster_number,
                            FILE *f, wchar_t *names[], uint32_t current_index,
                            uint32_t size) {
    uint32_t error_value = get_error_value(hdr);
    union DirEntry result;
    do {
        result = get_data_dir_one_cluster(hdr, cluster_number, f, names,
                                          current_index, size);
        if (is_valid_dir_entry(&result)) {
            return result;
        }
        cluster_number = get_next_cluster(hdr, cluster_number, f);
    } while (cluster_number >= 0x2 && cluster_number < error_value);

    return createNullDirEntry();
}

union DirEntry createNullDirEntry() {
    union DirEntry dummy;
    dummy.dir.DIR_NTRes = 1;
    return dummy;
}

bool is_valid_dir_entry(union DirEntry *result) {
    return (*result).dir.DIR_NTRes == 0;
}

union DirEntry get_dir_entry_helper(const struct BPB *hdr, FILE *f,
                                    uint32_t max_total_entries,
                                    wchar_t *names[], uint32_t current_index,
                                    uint32_t size) {
    union DirEntry dir_entry;
    wchar_t *desired_name = names[current_index];
    // all names in the directory are unique, so don't need to worry about
    // duplicate
    for (uint32_t i = 0; i < max_total_entries &&
                         fread(&dir_entry, ENTRY_SIZE_BYTES, 1, f) == 1;
         i++) {
        wchar_t directory_name[PATH_MAX] = {0};
        union DirEntry current_names[max_total_entries];
        uint32_t name_offset = 0;
        memcpy(&current_names[name_offset++], &dir_entry, ENTRY_SIZE_BYTES);

        if (dir_entry.dir.DIR_Name[0] == 0) {
            return createNullDirEntry();
        }

        if (dir_entry.dir.DIR_Name[0] == 0xE5) {
            continue; // free block
        }

        if (dir_entry.ldir.LDIR_Attr != ATTR_LONG_NAME) {
            uint32_t directory_cluster = get_associated_cluster(&dir_entry);

            if (!is_excluded_dir(&dir_entry)) { // there are times when there
                                                // are files without long name
                // there are times when it doesn't have long name
                wchar_t *temp_pointer = convert_short_name_wchar(&dir_entry, i);
                if (wcscmp(temp_pointer, desired_name) == 0 &&
                    dir_entry.dir.DIR_Name[0] != 0xe5) {
                    free(temp_pointer);
                    if (current_index + 1 == size) {
                        dir_entry = embed_offset(f, &dir_entry);
                        return dir_entry;
                    }

                    if (current_index + 1 != size &&
                        dir_entry.dir.DIR_Attr != ATTR_DIRECTORY) {
                        return createNullDirEntry(); // not the last entry but
                                                     // not a directory
                    }

                    return get_data_dir(hdr, directory_cluster, f, names,
                                        current_index + 1, size);
                }
            }

            // This is just . or .., otherwise it should have long name
            // implementation or it must be corrupted data
            bool is_zero_name = dir_entry.dir.DIR_Name[0] == 0x00;
            if (is_zero_name) {
                return createNullDirEntry();
            }
            if (is_excluded_dir(&dir_entry) &&
                desired_name[0] == dir_entry.dir.DIR_Name[0] &&
                desired_name[1] == dir_entry.dir.DIR_Name[1]) {
                if (current_index + 1 == size) {
                    dir_entry = embed_offset(f, &dir_entry);
                    return dir_entry;
                }

                if (current_index + 1 != size &&
                    dir_entry.dir.DIR_Attr != ATTR_DIRECTORY) {
                    return createNullDirEntry(); // not the last entry but not a
                                                 // directory
                }

                return get_data_dir(hdr, directory_cluster, f, names,
                                    current_index + 1, size);
            } else {
                continue;
            }
        }

        // get all the names until short entry
        while (dir_entry.dir.DIR_Attr == ATTR_LONG_NAME) {
            if (fread(&dir_entry, ENTRY_SIZE_BYTES, 1, f) != 1) {
                perror("fread");
                exit(EXIT_FAILURE);
            } // read the short entry
            memcpy(&current_names[name_offset++], &dir_entry, ENTRY_SIZE_BYTES);
        }

        uint32_t first_offset = name_offset - 2;
        uint8_t ordinal_value = current_names[first_offset + 1].ldir.LDIR_Ord;
        while ((ordinal_value & LAST_LONG_ENTRY) != LAST_LONG_ENTRY) {
            first_offset--;
            ordinal_value = current_names[first_offset].ldir.LDIR_Ord;
        }

        for (uint32_t j = first_offset; j < name_offset - 1; j++) {
            populate_directory_name(&current_names[j], directory_name);
        }

        uint32_t directory_cluster = get_associated_cluster(&dir_entry);

        bool is_zero_name = dir_entry.dir.DIR_Name[0] == 0x05;
        if (is_zero_name) {
            return createNullDirEntry();
        }

        if (wcscmp(directory_name, desired_name) == 0 &&
            dir_entry.dir.DIR_Name[0] != 0xe5) {
            if (current_index + 1 == size) {
                dir_entry = embed_offset(f, &dir_entry);
                return dir_entry;
            }

            if (current_index + 1 != size &&
                dir_entry.dir.DIR_Attr != ATTR_DIRECTORY) {
                return createNullDirEntry(); // not the last entry but not a
                                             // directory
            }

            return get_data_dir(hdr, directory_cluster, f, names,
                                current_index + 1, size);
        }
    }

    return createNullDirEntry();
}

union DirEntry embed_offset(FILE *f, union DirEntry *dir_entry) {
    uint64_t offset = ftell(f) - ENTRY_SIZE_BYTES;
    (*dir_entry).dir.OFFSET = offset;
    return (*dir_entry);
}

uint32_t get_associated_cluster(union DirEntry *dir_entry) {
    uint32_t directory_cluster;
    directory_cluster = (*dir_entry).dir.DIR_FstClusLO;
    directory_cluster |= ((*dir_entry).dir.DIR_FstClusHI << 16);
    return directory_cluster;
}

union DirEntry get_data_dir_one_cluster(const struct BPB *hdr,
                                        uint32_t cluster_number, FILE *f,
                                        wchar_t *names[],
                                        uint32_t current_index, uint32_t size) {
    uint32_t sector_number = get_data_sector_from_cluster(
        hdr, cluster_number, get_first_data_sector(hdr));
    uint32_t offset = convert_sector_to_byte_offset(hdr, sector_number);
    fseek(f, offset, SEEK_SET);
    uint32_t max_total_entries = get_entries_per_cluster(hdr);
    return get_dir_entry_helper(hdr, f, max_total_entries, names, current_index,
                                size);
}

union DirEntry get_dir_entry_on_name(const struct BPB *hdr, wchar_t **names,
                                     FILE *f, uint32_t current_index,
                                     uint32_t size) {
    uint32_t version = get_fat_version(hdr);
    if (version == 32) {
        return get_data_dir(hdr, hdr->fat32.BPB_RootClus, f, names,
                            current_index, size);
    } else {
        uint32_t first_root_dir_sector =
            hdr->BPB_RsvdSecCnt + (hdr->BPB_NumFATs * hdr->BPB_FATSz16);
        uint32_t offset =
            convert_sector_to_byte_offset(hdr, first_root_dir_sector);
        fseek(f, offset, SEEK_SET);
        return get_dir_entry_helper(hdr, f, hdr->BPB_RootEntCnt, names,
                                    current_index, size);
    }
}

void remove_fat_entry(const struct BPB *hdr, FILE *f, uint32_t cluster_number,
                      uint32_t *offset, uint32_t *fat_entry_bytes,
                      uint32_t *entry) {
    // just found out only need to support FAT32
    // preserve the top 4 bits, based on diagram, the second fat number should
    // be 1
    for (int i = 0; i < hdr->BPB_NumFATs; i++) {
        get_fat_offset_given_cluster(hdr, cluster_number, fat_entry_bytes,
                                     offset);
        uint32_t fat_table_copy_offset =
            hdr->fat32.BPB_FATSz32 * hdr->BPB_BytsPerSec * i + (*offset);
        fseek(f, fat_table_copy_offset, SEEK_SET);
        fread(entry, (*fat_entry_bytes), 1, f);
        (*entry) &= 0xF0000000;
        fseek(f, fat_table_copy_offset, SEEK_SET);
        fwrite(entry, (*fat_entry_bytes), 1, f);
    }

    // TODO: update FS Info (optional) + Update timing if required
}

uint32_t get_error_value(const struct BPB *hdr) {
    uint32_t error_value;
    switch (get_fat_version(hdr)) {
    case 32:
        error_value = 0xFFFFFF7;
        break;
    case 16:
        error_value = 0xFFF7;
        break;
    default:
        error_value = 0xFF7;
    }
    return error_value;
}

void remove_file(const struct BPB *hdr, union DirEntry file_entry, FILE *f) {
    uint32_t error_value = get_error_value(hdr);
    uint32_t cluster_number, offset, fat_entry_bytes;
    uint32_t entry, next_cluster;
    for (cluster_number = get_associated_cluster(&file_entry);
         cluster_number >= 0x2 && cluster_number < error_value;) {
        next_cluster = get_next_cluster(hdr, cluster_number, f);
        remove_fat_entry(hdr, f, cluster_number, &offset, &fat_entry_bytes,
                         &entry);
        cluster_number = next_cluster;
    }
    // change EOF to also free list
    remove_fat_entry(hdr, f, cluster_number, &offset, &fat_entry_bytes, &entry);

    // mark the DirEntry to unused
    mark_entry_unused(&file_entry, f);
}

void mark_entry_unused(union DirEntry *file_entry, FILE *f) {
    uint64_t dir_offset = (*file_entry).dir.OFFSET;
    uint8_t removed_byte = 0xE5;
    fseek(f, (long)dir_offset, SEEK_SET);
    fwrite(&removed_byte, 1, 1, f);

#ifdef DEBUG
    uint32_t *entry = malloc(32);
    fseek(f, (long)dir_offset, SEEK_SET);
    fread(entry, 32, 1, f);
    hexdump(entry, 32);
#endif
}

void remove_object(const struct BPB *hdr, union DirEntry dir_entry, FILE *f) {
    uint32_t cluster_number;

    if (dir_entry.dir.DIR_Attr == ATTR_DIRECTORY) {
        // remove every entry in the directory
        cluster_number = get_associated_cluster(&dir_entry);
        uint32_t error_value = get_error_value(hdr);
        do {
            remove_objects_one_cluster(hdr, cluster_number, f);
            cluster_number = get_next_cluster(hdr, cluster_number, f);
        } while (cluster_number >= 0x2 && cluster_number < error_value);

        // remove the directory itself
        mark_entry_unused(&dir_entry, f);
    } else {
        remove_file(hdr, dir_entry, f);
    }
}

void remove_objects_one_cluster(const struct BPB *hdr, uint32_t cluster_number,
                                FILE *f) {
    union DirEntry dir_entry;
    // all names in the directory are unique, so don't need to worry about
    // duplicate
    uint32_t max_total_entries = get_entries_per_cluster(hdr);
    union DirEntry to_be_removed[max_total_entries];
    uint32_t idx = 0;

    uint32_t sector_number = get_data_sector_from_cluster(
        hdr, cluster_number, get_first_data_sector(hdr));
    uint32_t offset = convert_sector_to_byte_offset(hdr, sector_number);
    fseek(f, offset, SEEK_SET);

    for (uint32_t i = 0; i < max_total_entries &&
                         fread(&dir_entry, ENTRY_SIZE_BYTES, 1, f) == 1;
         i++) {
        if (dir_entry.dir.DIR_Name[0] == 0) {
            break;
        }

        if (dir_entry.dir.DIR_Name[0] == 0xE5) {
            continue; // free block
        }

        if (dir_entry.dir.DIR_Attr == ATTR_LONG_NAME ||
            is_excluded_dir(&dir_entry)) {
            continue; // you don't want to delete .. and ., otherwise the entire
                      // fs is deleted
        }

        dir_entry = embed_offset(f, &dir_entry);
        memcpy(&to_be_removed[idx++], &dir_entry, sizeof(union DirEntry));
        bool is_zero_name = dir_entry.dir.DIR_Name[0] == 0x05;
        if (is_zero_name) {
            break;
        }
    }

    for (int i = 0; i < idx; i++) {
        remove_object(hdr, to_be_removed[i], f);
    }
}

void root_remove(const struct BPB *hdr, FILE *f) {
    uint32_t cluster_number = hdr->fat32.BPB_RootClus;
    uint32_t error_value = get_error_value(hdr);
    do {
        remove_objects_one_cluster(hdr, cluster_number, f);
        cluster_number = get_next_cluster(hdr, cluster_number, f);
    } while (cluster_number >= 0x2 && cluster_number < error_value);
}
