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

#ifndef _KEY_FINDER_H
#define _KEY_FINDER_H

#include <dirent.h>

// Header MAGICs
#define BOOT_MAGIC   "ANDROID!"

// buffer size for keyfile
#define KEYFILE_SIZE 96


int Check_If_New_Keyfile(const char *path_new_key_file, const char *full_path_keys);
int Test_KeyFile(const char *path_enczip, const char *path_keyfile);
int Run_BRUUTVEAL(const char *path_hboot_file, const char *path_encrypted_zip_file, const char *path_output_key_file);
int KeyFinder_CheckInputFile(const char *full_path_encrypted_zip_file, const char *full_path_hboot_file, const char *full_path_output_key_file);
int KeyFinder_CheckKeyfilesFolder(const char *full_path_encrypted_zip_file, const char *full_path_keys, const char *full_path_output_key_file);
int KeyFinder_CheckRuuvealKeys(const char *full_path_encrypted_zip_file);
int KeyFinder_TryForceExtraction(const char *full_path_encrypted_zip_file, const char *full_path_output_key_file);
int KeyFinder(const char *path_inp_enczipfiles, const char *full_path_keys, const char *full_path_hboot_file, const char *path_out_key_file);

#endif // _KEY_FINDER_H
