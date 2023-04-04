//
// Created by lauwsj on 4/4/23.
//

#ifndef FAT_COPY_FROM_IMAGE_H
#define FAT_COPY_FROM_IMAGE_H

void copy_from_image(const char *diskimg_path, const char *image_path,
                     const char *local_path);

void check_local_path_regular_if_exists(const char *local_path);

#endif // FAT_COPY_FROM_IMAGE_H
