/*
 * RUU_Decrypt_Tool
 * This file is part of the HTC RUU Decrypt Tool.
 *
 * Copyright 2016-2017 nkk71 <nkk71x@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _SYSTEM_IMAGE_H
#define _SYSTEM_IMAGE_H

// Header MAGICs
#define SPARSE_MAGIC   "\x3a\xff\x26\xed"

int CreateSystemIMG(const char *path_inp_sysimgfiles, const char *path_output_system_img_file);
int TestSystemIMG(const char *path_systemimg_file);
int MoveSystemIMGFiles(const char *path_inp_files, const char *path_outsystemimgs);

#endif // _SYSTEM_IMAGE_H
