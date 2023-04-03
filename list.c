//
// Created by lauwsj on 3/4/23.
//
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <wchar.h>

#include "list.h"
#include "common.h"
#include "inspection.h"

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

void list_fat(const char *diskimg_path) {
    off_t size;
    uint8_t *image;
    get_bpb_mmap(diskimg_path, &size, &image);
    const struct BPB *hdr = (const struct BPB *) image;

    FILE *f = fopen(diskimg_path, "rb");
    if (f == NULL) {
        perror("fopen");
        exit(1);
    }

    list_root_dir(hdr, f);
    munmap(image, size);
    fclose(f);
}

void list_data_dir_one_cluster(const struct BPB *hdr, uint32_t cluster_number, FILE *f, wchar_t *prefix) {
    uint32_t sector_number = get_sector_from_cluster(hdr, cluster_number, get_first_data_sector(hdr));
    uint32_t offset = convert_sector_to_byte_offset(hdr, sector_number);
    fseek(f, offset, SEEK_SET);

    // by default, mkfs.fat will support the long name implementation as shown in this trivia:
    // https://stackoverflow.com/questions/14123302/fat32-set-long-filename-and-8-3-filename-separately
    // read long name entry, to be honest this is linux ext4 limit, hopefully this is safe enough
    uint32_t max_total_entries = get_entries_per_cluster(hdr);
    read_dir_helper(hdr, f, max_total_entries, prefix);
}

void read_dir_helper(const struct BPB *hdr, FILE *f, uint32_t max_total_entries, wchar_t *prefix) {
    union DirEntry dir_entry;
    bool is_last = false;
    wchar_t* prefixes[max_total_entries];
    uint32_t next_entry[max_total_entries];
    uint32_t idx = 0;

    for (uint32_t i = 0;
         i < max_total_entries &&
         fread(&dir_entry, ENTRY_SIZE_BYTES, 1, f) == 1 &&
         !is_last;
         i++) {
        wchar_t directory_name[PATH_MAX] = {0};
        if (dir_entry.dir.DIR_Name[0] == 0) {
            is_last = true; // everything following this is free
            continue;
        }

        if (dir_entry.dir.DIR_Name[0] == 0xE5) {
            continue; // free block
        }

        if (dir_entry.ldir.LDIR_Attr != ATTR_LONG_NAME) {
            if (!is_excluded_dir(&dir_entry)) {
                 wprintf(L"%s\n", dir_entry.dir.DIR_Name);
            }

            continue;
        }

        populate_directory_name(&dir_entry, directory_name);
        uint8_t ordinal_value = dir_entry.ldir.LDIR_Ord;
        while (!isLastLongName(ordinal_value)) {
            if (fread(&dir_entry, ENTRY_SIZE_BYTES, 1, f) != 1) {
                perror("fread");
                exit(EXIT_FAILURE);
            } // read again

            populate_directory_name(&dir_entry, directory_name);
            ordinal_value = dir_entry.ldir.LDIR_Ord;
        }

        if (fread(&dir_entry, ENTRY_SIZE_BYTES, 1, f) != 1) {
            perror("fread");
            exit(EXIT_FAILURE);
        } // read the short entry
        if (is_excluded_dir(&dir_entry)) {
            continue;
        }

        if (dir_entry.dir.DIR_Attr == ATTR_DIRECTORY) { // supporting unicode
            uint32_t directory_cluster;
            wprintf(L"%ls%ls/\n", prefix, directory_name);

            wchar_t result[PATH_MAX]; // concatenate the path
            wcscpy(result, prefix);
            wcscat(result, directory_name);
            wcscat(result, L"/");

            directory_cluster = dir_entry.dir.DIR_FstClusLO;
            directory_cluster |= (dir_entry.dir.DIR_FstClusHI << 16);
            prefixes[idx] = result;
            next_entry[idx++] = directory_cluster;
        } else {
            wprintf(L"%ls%ls\n", prefix, directory_name);
        }
    }

    for (uint32_t i = 0; i < idx; i++) {
        list_data_dir(hdr, next_entry[i], f, prefixes[i]);
    }
}

bool is_excluded_dir(union DirEntry *dir_entry) {
    // its the short name already, most likely its . and ..
    for (uint32_t i = 2; i < 11; i++) {
        if ((*dir_entry).dir.DIR_Name[i] != 0x20) {
            return false;
        }
    }

    // reaching this point, means everything else from idx 2 - 10 is already 0x20 (space)
    bool is_current_directory = (*dir_entry).dir.DIR_Name[0] == 0x2e && (*dir_entry).dir.DIR_Name[1] == 0x20;
    bool is_prev_directory = (*dir_entry).dir.DIR_Name[0] == 0x2e && (*dir_entry).dir.DIR_Name[1] == 0x2e;
    if (is_prev_directory || is_current_directory) {
        return true;
    }

    return false;
}

bool isLastLongName(uint8_t ordinal_value) { return (ordinal_value == (LAST_LONG_ENTRY | 1)) || ordinal_value == 1; }

void populate_directory_name(union DirEntry *dir_entry, wchar_t *directory_name) {
    uint8_t ordinal_value = (*dir_entry).ldir.LDIR_Ord;
    uint32_t array_offset = (ordinal_value & 0x3F) - 1;
    array_offset *= 13;
    size_t ldir_name1_size = sizeof((*dir_entry).ldir.LDIR_Name1);
    size_t ldir_name2_size = sizeof((*dir_entry).ldir.LDIR_Name2);
    size_t ldir_name3_size = sizeof((*dir_entry).ldir.LDIR_Name3);
    for (int i = 0; i < ldir_name1_size / 2; i++) {
        directory_name[array_offset + i] = combine_bytes((*dir_entry).ldir.LDIR_Name1[i * 2 + 1],
                                                         (*dir_entry).ldir.LDIR_Name1[i * 2]);
    }
    array_offset += ldir_name1_size / 2;
    for (int i = 0; i < ldir_name2_size / 2; i++) {
        directory_name[array_offset + i] = combine_bytes((*dir_entry).ldir.LDIR_Name2[i * 2 + 1],
                                                         (*dir_entry).ldir.LDIR_Name2[i * 2]);
    }
    array_offset += ldir_name2_size / 2;
    for (int i = 0; i < ldir_name3_size / 2; i++) {
        directory_name[array_offset + i] = combine_bytes((*dir_entry).ldir.LDIR_Name3[i * 2 + 1],
                                                         (*dir_entry).ldir.LDIR_Name3[i * 2]);
    }
}

uint32_t get_sector_from_cluster(const struct BPB *hdr, uint32_t N, uint32_t first_data_sector) {
    return (N - 2) * (hdr->BPB_SecPerClus) + first_data_sector;
}

wchar_t combine_bytes(uint8_t high_byte, uint8_t low_byte) {
    wchar_t result = ((wchar_t) high_byte << 8) | (wchar_t) low_byte;
    return result;
}

uint32_t get_entries_per_cluster(const struct BPB *hdr) {
    uint32_t total_bytes_per_cluster = hdr->BPB_BytsPerSec * hdr->BPB_SecPerClus;
    return total_bytes_per_cluster / ENTRY_SIZE_BYTES;
}

uint32_t get_next_cluster(const struct BPB *hdr, uint32_t cluster_number, FILE *f) {
    uint32_t fat_offset, fat_entry_bytes;
    switch (get_fat_version(hdr)) {
        case 32:
            fat_offset = cluster_number * 4;
            fat_entry_bytes = 4;
            break;
        case 16:
            fat_offset = cluster_number * 2;
            fat_entry_bytes = 2;
            break;
        default:
            /**
             * Since its stored in 3 bytes, we can get upper half or lower half
             * attempt to get the lower half and read the two fat entries
             */
            fat_offset = cluster_number + cluster_number / 2;
            fat_entry_bytes = 2;
    }

    uint32_t entry;
    uint32_t offset = hdr->BPB_RsvdSecCnt * hdr->BPB_BytsPerSec + fat_offset;
    fseek(f, offset, SEEK_SET);
    fread(&entry, fat_entry_bytes, 1, f);
    switch (get_fat_version(hdr)) {
        case 32:
            return entry & 0x0FFFFFFF;
        case 16:
            return entry & 0x0000FFFF;
        default:
            if (cluster_number % 2 == 1) {
                // we are getting the last half of the three bytes, there are 4 bits noise
                return (entry >> 4) & 0x00000FFF;
            } else {
                // we are getting the first half
                return entry & 0x00000FFF;
            }
    }
}

void list_data_dir(const struct BPB *hdr, uint32_t cluster_number, FILE *f, wchar_t *prefix) {
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

    do {
        list_data_dir_one_cluster(hdr, cluster_number, f, prefix);
        cluster_number = get_next_cluster(hdr, cluster_number, f);
#ifdef DEBUG
        wprintf(L"Current cluster: %X", cluster_number);
#endif
    } while (cluster_number > 0x2 && cluster_number < error_value);
}

void list_root_dir(const struct BPB *hdr, FILE *f) {
    uint32_t version = get_fat_version(hdr);
    if (version == 32) {
        list_data_dir(hdr, hdr->fat32.BPB_RootClus, f, L"/");
    } else {
        uint32_t first_root_dir_sector = hdr->BPB_RsvdSecCnt + (hdr->BPB_NumFATs * hdr->BPB_FATSz16);
        uint32_t offset = convert_sector_to_byte_offset(hdr, first_root_dir_sector);
        fseek(f, offset, SEEK_SET);
        read_dir_helper(hdr, f, hdr->BPB_RootEntCnt, L"/");
    }
}
