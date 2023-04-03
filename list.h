//
// Created by lauwsj on 3/4/23.
//

#ifndef FAT_LIST_H
#define FAT_LIST_H

#define ENTRY_SIZE_BYTES 32
#define LAST_LONG_ENTRY 0x40
#define DEFAULT_FAT_NUMBER 1

#include "fat.h"

void list_fat(const char *diskimg_path);


#endif //FAT_LIST_H
