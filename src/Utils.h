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

#ifndef _UTILS_H
#define _UTILS_H

#include <dirent.h>
#include <sys/stat.h>

#include <string>


// MAX_EXEC_ARGS is the maximum number of arguments passed through exec() calls,
// needs to accommodate the max number of args when using run_program
// including the max system*.img* files
#define MAX_EXEC_ARGS 60


const char *get_basename(const char *path_file);
std::string convert_to_absolute_path(const char *path);
std::string convert_to_absolute_path(const std::string path);
std::string get_absolute_cwd(void);
#if defined(__CYGWIN__)
int win_path_has_spaces(const char *path);
#endif

int change_dir(const char *path);
int change_dir(const std::string &path);

int copy_file(const char *source, const char *destination, int skip = 0);
int copy_file(const std::string &source, const std::string &destination, int skip = 0);

int append_file(const char *source, const char *destination);

int move_file(const char *source, const char *destination);
int move_file(const std::string &source, const std::string &destination);
int move_file(const char *filename, const char *source_path, const char *destination_path);

int delete_file(const char *source);
int delete_file(const std::string &source);

int delete_dir_contents(const char *path);

off_t file_size(const char *path_file);

int check_magic(const char *file_name, int offset, const char *magic);


int run_program(const char *bin_to_run, char *argv[]);
int run_program(const char *bin_to_run, ...);


int select_files_any(const struct dirent *de);
int select_files_zip(const struct dirent *de);
int select_files_systemimg(const struct dirent *de);
int select_files_keyfiles(const struct dirent *de);
int select_dirs(const struct dirent *de);
int versionsort_scandir(const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *));
void free_dirent_entry_list(struct dirent **entry_list, int count);

std::string find_file_from_pattern(const char *path, const char *pattern);

#endif // _UTILS_H
