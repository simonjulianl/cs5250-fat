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

uint32_t get_first_sector_of_cluster(const struct BPB *hdr, uint32_t N, uint32_t first_data_sector);

uint32_t get_first_root_dir_sector(const struct BPB *hdr);

void populate_directory_name(union DirEntry *dir_entry, wchar_t *directory_name);

bool isLastLongName(uint8_t ordinal_value);

wchar_t combine_bytes(uint8_t high_byte, uint8_t low_byte);;

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
    uint32_t root_dir_sector = get_first_root_dir_sector(hdr);

    FILE *f = fopen(diskimg_path, "rb");
    if (f == NULL) {
        perror("fopen");
        exit(1);
    }
    uint32_t offset = convert_sector_to_byte_offset(hdr, root_dir_sector);
    fseek(f, offset, SEEK_SET);
    // TODO: Print current directory
    union DirEntry dir_entry;

    // by default, mkfs.fat will support the long name implementation as shown in this trivia:
    // https://stackoverflow.com/questions/14123302/fat32-set-long-filename-and-8-3-filename-separately
    bool is_last = false;
    // read long name entry, to be honest this is linux ext4 limit, hopefully this is safe enough
    wchar_t directory_name[PATH_MAX] = {0};
    while (fread(&dir_entry, ENTRY_SIZE_BYTES, 1, f) == 1 && !is_last) {
        if (dir_entry.dir.DIR_Name[0] == 0) {
            is_last = true; // everything following this is free
            continue;
        }

        if (dir_entry.dir.DIR_Name[0] == 0xE5) {
            continue; // free block
        }

        wmemset(directory_name, L'\0', PATH_MAX);
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
        } // read the short entry but don't need to use it

        wprintf(L"%ls\n", directory_name);
    }

    munmap(image, size);
    fclose(f);
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

uint32_t get_first_sector_of_cluster(const struct BPB *hdr, uint32_t N, uint32_t first_data_sector) {
    return (N - 2) * (hdr->BPB_SecPerClus) + first_data_sector;
}

uint32_t get_first_root_dir_sector(const struct BPB *hdr) {
    uint32_t version = get_fat_version(hdr);
    if (version == 32) {
        return get_first_sector_of_cluster(hdr, hdr->fat32.BPB_RootClus, get_first_data_sector(hdr));
    } else {
        return hdr->BPB_RsvdSecCnt + (hdr->BPB_NumFATs * hdr->BPB_FATSz16);
    }
}

wchar_t combine_bytes(uint8_t high_byte, uint8_t low_byte) {
    wchar_t result = ((wchar_t) high_byte << 8) | (wchar_t) low_byte;
    return result;
}
