//
// Created by lauwsj on 4/4/23.
//

#include <ctype.h>
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

void update_dir_entry_cluster(FILE *f, const union DirEntry *file_entry,
                              uint32_t fat_entry);

void clear_up_resources(FILE *lf, off_t size, uint8_t *image, FILE *f,
                        wchar_t *const *image_path_names, int idx_image);

bool is_valid_short_filename_char(char c);

void create_short_filename(const char *filename, char *short_filename);

unsigned char generate_long_name_checksum(unsigned char *short_name);

void update_dir_entry_size(FILE *f, const union DirEntry *file_entry,
                           uint32_t file_size);

bool is_valid_long_filename_char(char c);

uint32_t get_single_free_fat_entry(const struct BPB *hdr, FILE *f);
void copy_from_local(const char *diskimg_path, const char *local_path,
                     const char *image_path) {
    // get or open the lo
    check_local_path_regular_if_exists(local_path);

    const char *filename =
        strrchr(image_path, '/') + 1; // will give <filename>.<ext>
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
        // check if directory exists
        uint32_t dir_cluster_number;
        union DirEntry parent_dir_entry =
            get_dir_entry_on_name(hdr, image_path_names, f, 0, idx_image - 1);
        if (idx_image == 1) {
            // only root dir
            dir_cluster_number = hdr->fat32.BPB_RootClus;
        } else {
            parent_dir_entry = get_dir_entry_on_name(hdr, image_path_names, f,
                                                     0, idx_image - 1);
            if (!is_valid_dir_entry(&parent_dir_entry)) {
                clear_up_resources(lf, size, image, f, image_path_names,
                                   idx_image);
                perror("Parent directory to the file doesn't exist");
                exit(EXIT_FAILURE);
            }

            if (parent_dir_entry.dir.DIR_Attr != ATTR_DIRECTORY) {
                clear_up_resources(lf, size, image, f, image_path_names,
                                   idx_image);
                perror("Parent file is a regular file, not a directory");
                exit(EXIT_FAILURE);
            }

            dir_cluster_number = get_associated_cluster(&parent_dir_entry);
        }

        // generate the long dir entries + short entry
        if (strlen(filename) > 255) {
            perror("Exceeding 255 characters, cannot create the file");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < strlen(filename); i++) {
            if (!is_valid_long_filename_char(filename[i])) {
                clear_up_resources(lf, size, image, f, image_path_names,
                                   idx_image);
                perror("Not a valid FAT32 long filename character");
                exit(EXIT_FAILURE);
            }
        }

        char short_filename[11];
        create_short_filename(filename, short_filename);
        for (int i = 0; i < 11; i++) {
            if (!is_valid_short_filename_char(short_filename[i])) {
                perror("Not a valid FAT32 short filename char");
                exit(EXIT_FAILURE);
            }
        }

        // account for NULL terminator
        size_t filename_length = strlen(filename) + 1;
        uint8_t long_entry_required = (filename_length + 13 - 1) / 13;
        uint32_t total_entries_required =
            long_entry_required + 1; // account for short entry

        if (total_entries_required > get_entries_per_cluster(hdr)) {
            perror("Cannot store the long filename and short file in a "
                   "consecutive cluster");
            exit(EXIT_FAILURE);
        }

        uint32_t checksum =
            generate_long_name_checksum((unsigned char *)short_filename);

        union DirEntry short_dir;
        for (int i = 0; i < 11; i++) {
            short_dir.dir.DIR_Name[i] = short_filename[i];
        }
        short_dir.dir.DIR_Attr = 0; // must be 0 when a file is created
        short_dir.dir.DIR_NTRes = 0;
        short_dir.dir.DIR_FstClusLO = 0;
        short_dir.dir.DIR_FstClusHI = 0;
        short_dir.dir.DIR_FileSize = 0;
        // again assuming the time doesn't need to be updated

        union DirEntry long_dirs[long_entry_required];
        wchar_t w_filename[filename_length];
        mbstowcs(w_filename, filename, filename_length);
        uint32_t idx = 0;
        for (uint8_t i = 0; i < long_entry_required; i++) {
            union DirEntry new_long_entry;
            for (int k = 0; k < 13; k++, idx++) {
                wchar_t ch;
                if (idx < filename_length) {
                    ch = w_filename[idx];
                } else {
                    ch = 0xFFFF;
                }
                if (k < 5) {
                    new_long_entry.ldir.LDIR_Name1[k * 2] =
                        (unsigned char)ch & 0xFF; // low bytes
                    new_long_entry.ldir.LDIR_Name1[k * 2 + 1] =
                        (unsigned char)((ch >> 8) & 0xFF); // high bytes
                } else if (k < 11) {
                    new_long_entry.ldir.LDIR_Name2[(k - 5) * 2] =
                        (unsigned char)ch & 0xFF;
                    new_long_entry.ldir.LDIR_Name2[(k - 5) * 2 + 1] =
                        (unsigned char)((ch >> 8) & 0xFF);
                } else {
                    new_long_entry.ldir.LDIR_Name3[(k - 11) * 2] =
                        (unsigned char)ch & 0xFF;
                    new_long_entry.ldir.LDIR_Name3[(k - 11) * 2 + 1] =
                        (unsigned char)((ch >> 8) & 0xFF);
                }
            }
            new_long_entry.ldir.LDIR_Attr = ATTR_LONG_NAME;
            new_long_entry.ldir.LDIR_Chksum = checksum;
            new_long_entry.ldir.LDIR_Ord = i + 1;
            new_long_entry.ldir.LDIR_Type = 0;
            new_long_entry.ldir.LDIR_FstClusLO = 0;

            if (i == long_entry_required - 1) {
                // last entry
                new_long_entry.ldir.LDIR_Ord |= LAST_LONG_ENTRY;
            }

            long_dirs[i] = new_long_entry;
        }

#ifdef DEBUG
        hexdump(long_dirs, 32);
        hexdump(long_dirs + 1, 32);
        wprintf(L"%s", short_filename);
#endif

        /*
         * A really simple way to assign a new file is just by allocating
         * a new cluster, and put the file there (not the best for space
         * utilization), obviously can be improved
         */

        // get a free cluster
        uint32_t extra_fat_entry = get_single_free_fat_entry(hdr, f);
        if (extra_fat_entry == 0) {
            perror("No more cluster available");
            exit(EXIT_FAILURE);
        }

        // write the dir entry into the new cluster
        uint32_t sector_number = get_data_sector_from_cluster(
            hdr, extra_fat_entry, get_first_data_sector(hdr));

        for (int i = long_entry_required - 1, j = 0; i > -1; i--, j++) {
            union DirEntry current_long_entry = long_dirs[i];
            fseek(f, sector_number * hdr->BPB_BytsPerSec + j * ENTRY_SIZE_BYTES,
                  SEEK_SET);
            fwrite(&current_long_entry, ENTRY_SIZE_BYTES, 1, f);
        }

        // write the dirs
        fseek(f,
              sector_number * hdr->BPB_BytsPerSec +
                  long_entry_required * ENTRY_SIZE_BYTES,
              SEEK_SET);
        fwrite(&short_dir, ENTRY_SIZE_BYTES, 1, f);

        uint32_t cluster_number, prev_cluster_number = 0,
                                 error_value = get_error_value(hdr);

        for (cluster_number = dir_cluster_number;
             cluster_number >= 0x2 && cluster_number < error_value;) {
            prev_cluster_number = cluster_number;
            cluster_number = get_next_cluster(hdr, cluster_number, f);
        }

        // update the FAT entry
        for (int i = 0; i < hdr->BPB_NumFATs; i++) {
            uint32_t fat_entry_bytes;
            uint32_t offset, entry;
            get_fat_offset_given_cluster(hdr, prev_cluster_number,
                                         &fat_entry_bytes, &offset);
            fseek(f, offset, SEEK_SET);
            fread(&entry, 4, 1, f);
            entry &= 0xF0000000;
            entry |= extra_fat_entry;
            fseek(f, offset, SEEK_SET);
            fwrite(&entry, 4, 1, f);

            // set the new entry of the fat to be EOF
            get_fat_offset_given_cluster(hdr, extra_fat_entry, &fat_entry_bytes,
                                         &offset);
            fseek(f, offset, SEEK_SET);
            fread(&entry, 4, 1, f);
            entry &= 0xF0000000;
            entry |= 0x0FFFFFFF;
            fseek(f, offset, SEEK_SET);
            fwrite(&entry, 4, 1, f);
        }

        // try to insert again
        dir_entry =
            get_dir_entry_on_name(hdr, image_path_names, f, 0, idx_image);

        mark_fat_file_as_free(hdr, f, &dir_entry);
        dir_entry =
            get_dir_entry_on_name(hdr, image_path_names, f, 0, idx_image);

#ifdef DEBUG
        hexdump(&dir_entry, 32);
#endif

        write_local_to_image(lf, hdr, f, &dir_entry);
    }

    clear_up_resources(lf, size, image, f, image_path_names, idx_image);
}

uint32_t get_single_free_fat_entry(const struct BPB *hdr, FILE *f) {
    uint32_t fat_starting_offset = hdr->BPB_BytsPerSec * hdr->BPB_RsvdSecCnt;

    // end of cluster can be indicated using OR mask 0x0FFFFFFF
    uint32_t total_entry_fat = hdr->fat32.BPB_FATSz32 * hdr->BPB_BytsPerSec / 4;

    for (uint32_t i = hdr->fat32.BPB_RootClus + 1; i < total_entry_fat; i++) {
        uint32_t fat_entry;
        fseek(f, fat_starting_offset + i * 4, SEEK_SET);
        fread(&fat_entry, 4, 1, f);

        if ((fat_entry & 0x0FFFFFFF) == 0x00000000) {
            return i;
        }
    }

    return 0;
}

void create_short_filename(const char *filename, char *short_filename) {
    char basename[8];
    char extension[3];

    bool should_truncate = false;
    int i, j;
    for (i = 0, j = 0; i < strlen(filename); i++, j++) {
        if (filename[i] == '.') {
            break;
        }

        if (filename[i] != ' ' && j < 8) {
            if (filename[i] >= 'a' && filename[i] <= 'z') {
                basename[j] = toupper(filename[i]);
            } else {
                basename[j] = filename[i];
            }
        }
    }

    if (j > 8) {
        should_truncate = true;
    }

    while (j < 8) {
        basename[j++] = ' ';
    }

    if (filename[i] == '.') {
        for (i = i + 1, j = 0; i < strlen(filename); i++) {
            if (filename[i] != ' ' && j < 3) {
                if (filename[i] >= 'a' && filename[i] <= 'z') {
                    extension[j++] = toupper(filename[i]);
                } else {
                    extension[j++] = filename[i];
                }
            }
        }
    }

    while (j < 3) {
        basename[j++] = ' ';
    }

    for (i = 0; i < 11; i++) {
        if (i < 8) {
            short_filename[i] = basename[i];
        } else {
            short_filename[i] = extension[i - 8];
        }
    }

    if (should_truncate) {
        short_filename[6] = '~';
        short_filename[7] = '1';
    }
}

void clear_up_resources(FILE *lf, off_t size, uint8_t *image, FILE *f,
                        wchar_t *const *image_path_names, int idx_image) {
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
    if (file_size > UINT32_MAX) {
        perror("File is too big, unable to allocate it");
        exit(EXIT_FAILURE);
    }

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
    uint32_t total_entry_fat = hdr->fat32.BPB_FATSz32 * hdr->BPB_BytsPerSec / 4;

    for (uint32_t i = hdr->fat32.BPB_RootClus + 1;
         counter < cluster_required && i < total_entry_fat; i++) {
        // seek the cluster
        uint32_t fat_entry;
        fseek(f, fat_starting_offset + i * 4, SEEK_SET);
        fread(&fat_entry, 4, 1, f);
        if ((fat_entry & 0x0FFFFFFF) == 0x00000000) {
            fat_entries[counter++] = i; // ith fat entry
        }
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
        uint32_t sector = get_data_sector_from_cluster(
            hdr, fat_entries[current_cluster_index],
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
    update_dir_entry_cluster(f, dir_entry, fat_entries[0]);
    update_dir_entry_size(f, dir_entry, file_size);
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
         cluster_number >= 0x2 && cluster_number < error_value;) {
        next_cluster = get_next_cluster(hdr, cluster_number, f);
        remove_fat_entry(hdr, f, cluster_number, &offset, &fat_entry_bytes,
                         &entry);
        cluster_number = next_cluster;
    }

    // change EOF to also free list
    remove_fat_entry(hdr, f, cluster_number, &offset, &fat_entry_bytes, &entry);

    // mark the cluster associated with this entry to be 0
    update_dir_entry_cluster(f, file_entry, 0x00000000);
    update_dir_entry_size(f, file_entry, 0x00000000);
    // Note: assuming that the CrtTime and WrtTime
    // should be updated by the driver, not this CLI tool
    // Therefore those values won't be updated here
}

void update_dir_entry_cluster(FILE *f, const union DirEntry *file_entry,
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

bool is_valid_short_filename_char(char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' ||
        (c >= '0' && c <= '9') || c == '$' || c == '%' || c == '\'' ||
        c == '-' || c == '_' || c == '@' || c == '~' || c == '`' || c == '!' ||
        c == '(' || c == ')' || c == '{' || c == '}' || c == '^' || c == '#' ||
        c == '&' || c == ' ') {
        return true;
    }
    return false;
}

unsigned char generate_long_name_checksum(unsigned char *short_name) {
    // short name size must be 11
    unsigned char sum = 0;
    for (short name_len = 11; name_len != 0; name_len--) {
        sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + *short_name++;
    }

    return sum;
}

void update_dir_entry_size(FILE *f, const union DirEntry *file_entry,
                           uint32_t file_size) {
    uint32_t file_size_offset = file_entry->dir.OFFSET + 28;

    fseek(f, file_size_offset, SEEK_SET);
    fwrite(&file_size, 4, 1, f);
}

bool is_valid_long_filename_char(char c) {
    if (is_valid_short_filename_char(c) || (c == '+' || c == ';' || c == ',' ||
                                            c == '=' || c == '[' || c == ']')) {
        return true;
    }
    return false;
}
