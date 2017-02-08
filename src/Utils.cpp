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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/wait.h>
#include <errno.h>
#include <fnmatch.h>

#include <string>
#include <fstream>
#include <iostream>

#if defined(__CYGWIN__)
	#include <sys/cygwin.h>
#endif


#if defined(__CYGWIN__) || defined( __APPLE__)
	// scandir versionsort is missing in cygwin and mac
	#include "versionsort/strverscmp.c"
	#include "versionsort/versionsort.c"
#endif


#include "Common.h"
#include "Utils.h"



// =====================================================================
// use this basename for portability (for mac os)
const char *get_basename(const char *path_file)
{
	//note: we're assuming it's not a path ending with /
	//      since it wont be in this program
	const char *last_slash = strrchr(path_file, '/');

	if (last_slash == NULL)
		return path_file;
	else
		return (last_slash+1);
}
// =====================================================================
// file operations
// ---------------------------------------------------------------------
std::string convert_to_absolute_path(const char *path)
{
#if defined(__CYGWIN__)
	char winpath[PATH_MAX];

	if (cygwin_conv_path(CCP_ABSOLUTE | CCP_POSIX_TO_WIN_A, path, winpath, PATH_MAX) != 0) {
		perror("cygwin_conv_path");
		// rasie aport signal instead?
		return NULL;
	}
	else {
		// cygwin doesnt seem to care about mixed usage of \ and /, but for consistency
		int i;
		int len = strlen(winpath);

		for (i = 0; i < len; i++) {
			if (winpath[i] == '\\')
				winpath[i] = '/';
		}

		return winpath;
	}
#else
	return path;
#endif
}

std::string convert_to_absolute_path(const std::string path)
{
	return convert_to_absolute_path(path.c_str());
}

std::string get_absolute_cwd(void)
{
	return convert_to_absolute_path(getcwd(NULL, 0));
}
// ---------------------------------------------------------------------
#if defined(__CYGWIN__)
int win_path_has_spaces(const char *path)
{
	std::string abs_path = convert_to_absolute_path(path);
	if (abs_path.find(' ') !=  std::string::npos)
		return 1;
	else
		return 0;
}
#endif
// ---------------------------------------------------------------------
int change_dir(const char *path)
{
	if (chdir(path) != 0) {
		PRINT_ERROR("Couldn't cd to '%s'", path);
		return 1;
	}
	else
		return 0;
}

int change_dir(const std::string *path)
{
	return change_dir(path->c_str());
}

int change_dir(const std::string path)
{
	return change_dir(path.c_str());
}
// ---------------------------------------------------------------------
//int copy_file(const char *source, const char *destination, int skip = 0)
int copy_file(const char *source, const char *destination, int skip)
{
	int exit_code = 0;

	std::ifstream srcfile(source, std::ios::binary);
	std::ofstream dstfile(destination, std::ios::binary | std::ios::out);

	dstfile << srcfile.seekg(skip).rdbuf();

	srcfile.close();
	dstfile.close();

	if (!dstfile) {
		PRINT_ERROR("in copy_file, from '%s' to '%s'", source, destination);
		exit_code = 3;
	}
	return exit_code;
}

//int copy_file(const std::string *source, const std::string *destination, int skip = 0)
int copy_file(const std::string *source, const std::string *destination, int skip)
{
	return copy_file(source->c_str(), destination->c_str(), skip);
}
// ---------------------------------------------------------------------
int append_file(const char *source, const char *destination)
{
	int exit_code = 0;

	std::ifstream srcfile(source, std::ios::binary);
	std::ofstream dstfile(destination, std::ios::binary | std::ios::out | std::ios::app);

	dstfile << srcfile.rdbuf();

	srcfile.close();
	dstfile.close();

	if (!dstfile) {
		PRINT_ERROR("in append_file, from '%s' to '%s'", source, destination);
		exit_code = 3;
	}

	return exit_code;
}
// ---------------------------------------------------------------------
int move_file(const char *source, const char *destination)
{
	int res = rename(source, destination);

	if (res)
		return errno;
	else
		return 0;
}

int move_file(const std::string *source, const std::string *destination)
{
	return move_file(source->c_str(), destination->c_str());
}

int move_file(const char *filename, const char *source_path, const char *destination_path)
{
	std::string src = (std::string) source_path + "/" + filename;
	std::string dst = (std::string) destination_path + "/" + filename;

	return move_file(&src, &dst);
}
// ---------------------------------------------------------------------
int delete_file(const char *source)
{
	int res = remove(source);

	if (res)
		return errno;
	else
		return 0;
}

int delete_file(const std::string *source)
{
	return delete_file(source->c_str());
}

int delete_dir_contents(const char *path)
{
	DIR *dp = opendir(path);
	struct dirent *de;
	char path_file[PATH_MAX];

	while ( (de = readdir(dp)) != NULL )
	{
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		sprintf(path_file, "%s/%s", path, de->d_name);
		remove(path_file);
	}
	closedir(dp);
	return 0;
}

off_t file_size(const char *path_file)
{
	struct stat st;

	if (stat(path_file, &st) == 0)
		return st.st_size;
	else
		return 0;
}

// =====================================================================

int check_magic(const char *file_name, int offset, const char *magic)
{
	int exit_code = 0; //false
	char hdr[10];
	FILE * fp = fopen(file_name, "rb");

	if (fp == NULL) {
		PRINT_ERROR("Couldn't open file '%s', aborting!", file_name);
		exit_code = 0;
	}

	else {
		if ((exit_code = fseek(fp, offset, SEEK_SET))) {
			PRINT_ERROR("fseek error (err=%i)", exit_code);
		}
		else {
			fread(hdr, 1, sizeof(hdr), fp);
			exit_code = ferror(fp);
		}
		fclose(fp);

		if (exit_code) {
			PRINT_ERROR("Couldn’t read file header, aborting (err=%i)!", exit_code);
			exit_code = 0;
		}

		else if (strncmp(hdr, magic, strlen(magic)) == 0)
			exit_code = 1;
		else
			exit_code = 0;
	}

	return exit_code;
}

// =====================================================================
// run external tools
// ---------------------------------------------------------------------
int run_program(const char *bin_to_run, char *argv[])
{
	int exit_code;

	pid_t child_pid = fork();

	if (child_pid == -1) {
		PRINT_ERROR("could not fork child process!");
		exit_code = -1;
		return exit_code;
	}

	if (child_pid == 0) {
		// i am parent, go ahead and exec child
		int i, j;
		char *exec_args[MAX_EXEC_ARGS];

		i = 0;
		j = 0;

		std::string full_path_to_bin_file = full_path_to_bins + "/" + bin_to_run;

		exec_args[i++] = (char *)bin_to_run;

		if (argv == NULL) {
			exec_args[i++] = NULL;
		}
		else {
			do {
				exec_args[i++] = argv[j++];
			} while (exec_args[i-1] != NULL);
		}

		if (access(full_path_to_bin_file.c_str(), F_OK) == 0) {
			if (print_debug_info) {
				printf("[DBG] about to execv (run internal program): '%s'\n", bin_to_run);
				i = 0;
				while (exec_args[i] != NULL) {
					printf("[DBG]    '%s'\n", exec_args[i++]);
				}
				printf("\n");
			}
			execv(full_path_to_bin_file.c_str(), exec_args); // our binaries
		}
		else {
			if (print_debug_info) {
				printf("[DBG] about to execvp (run system program): '%s'\n", bin_to_run);
				i = 0;
				while (exec_args[i] != NULL) {
					printf("[DBG]    '%s'\n", exec_args[i++]);
				}
				printf("\n");
			}
			execvp(bin_to_run, exec_args); // OS provided binaries
		}

		// we should not get here unless an error in exec() occurred
		PRINT_ERROR("something went wrong with exec() (errno=%i '%s')!", errno, strerror(errno));
		if (access(full_path_to_bin_file.c_str(), F_OK) == 0)
			printf("offending execv: '%s'", full_path_to_bin_file.c_str());
		else
			printf("offending execvp: '%s'", bin_to_run);

		i = 0;
		while (exec_args[i] != NULL) {
			printf(" '%s'", exec_args[i++]);
		}
		printf("\n");

		// this is not working as intended: raise(SIGINT); // abort program

		exit_code = -2;
		return exit_code;
	}

	// now wait for child to exit an return code
	int status;
	waitpid(child_pid, &status, 0); //?? while (waitpid(-1, &status, 0) != child_pid);
	if (WIFEXITED(status)) {
		// child exited normally, get return value
		WEXITSTATUS(status);
		exit_code = status >> 8;
	}
	else {
		PRINT_ERROR("child exited abnormally (status=%i, errno=%i '%s')", status, errno, strerror(errno));
		exit_code = -3;
	}

	return exit_code;
}

// note: the last argument passed has to be NULL
int run_program(const char *bin_to_run, ...)
{
	int i;
	char *exec_args[MAX_EXEC_ARGS];
	va_list ap;
	va_start(ap, bin_to_run);

	i = 0;

	do {
		exec_args[i++] = va_arg(ap, char *);
	} while (exec_args[i-1] != NULL);

	va_end(ap);

	return run_program(bin_to_run, exec_args);
}
// =====================================================================


// =====================================================================
// scandir stuff   (consider adding: de->d_type == DT_REG)
// ---------------------------------------------------------------------
int select_files_any(const struct dirent *de)
{
	if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
		return 0;
	else
		return 1;
}

int select_files_zip(const struct dirent *de)
{
	std::string file_name = de->d_name;

	if (file_name.size() >= 4 && file_name.substr(file_name.size()-4) == ".zip")
		return 1;
	else
		return 0;
}

int select_files_systemimg(const struct dirent *de)
{
	std::string file_name = de->d_name;

	// has to start with 'system' and contain '.img'
	if ((strncmp(file_name.c_str(), "system", 6) == 0) && (file_name.find(".img") != std::string::npos))
		return 1;
	else
		return 0;
}

int select_files_keyfiles(const struct dirent *de)
{
	std::string file_name = de->d_name;

	if (file_name.size() >= 4 && file_name.substr(file_name.size()-4) == ".bin")
		return 1;
	else
		return 0;
}

int select_dirs(const struct dirent *de)
{
	if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
		return 0;
	else if (de->d_type == DT_DIR)
		return 1;
	else
		return 0;
}

int versionsort_scandir(const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *))
{
	return scandir(dirp, namelist, filter, versionsort);
}

void free_dirent_entry_list(struct dirent **entry_list, int count)
{
	int i;

	for (i = 0; i < count; i++)
		free(entry_list[i]);
	free(entry_list);
}

int is_scandir_error(struct dirent **entry_list, int count)
{
	if (count < 0) {
		PRINT_ERROR("scandir error");
		return 1;
	} else if (count == 0) {
		PRINT_ERROR("no files found");
		free_dirent_entry_list(entry_list, count);
		return 1;
	}
	return 0;
}


std::string find_file_from_pattern(const char *path, const char *pattern)
{
	DIR *dp = opendir(path);
	struct dirent *de;
	std::string path_file;

	while ( (de = readdir(dp)) != NULL )
	{
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		if (fnmatch(pattern, de->d_name, FNM_FILE_NAME | FNM_CASEFOLD) == 0) {
			path_file = path;
			path_file += "/";
			path_file += de->d_name;
			break;
		}
	}
	closedir(dp);

	return path_file;
}
// =====================================================================
