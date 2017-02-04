/*
 * RUU_Decrypt_Tool.cpp
 * 
 * Copyright 2016 nkk71 <nkk71@ubuntu>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <fnmatch.h>

#include <string>
#include <fstream>
#include <iostream>

// =====================================================================
// OS dependant includes
// ---------------------------------------------------------------------
#if defined( __APPLE__)

// versionsort is also not present in mac
#include "versionsort/strverscmp.c"
#include "versionsort/versionsort.c"
// mac specific header
#include <mach-o/dyld.h>

#endif


#if defined(__CYGWIN__)

#include <sys/cygwin.h>

// scandir stuff missing in cygwin
#include "versionsort/strverscmp.c"
#include "versionsort/versionsort.c"

#endif
// =====================================================================


// =====================================================================
// AIK paths relative to bin/
// ---------------------------------------------------------------------
//#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
#if defined(__CYGWIN__)

#define AIK_BASE		"AIK-Windows"
#define AIK_UNPACK		AIK_BASE"/unpackimg.bat"
#define AIK_CLEANUP		AIK_BASE"/cleanup.bat"

#elif defined(__APPLE__)

#define AIK_BASE		"AIK-OSX"
#define AIK_UNPACK		AIK_BASE"/unpackimg.sh"
#define AIK_CLEANUP		AIK_BASE"/cleanup.sh"

#else

#define AIK_BASE		"AIK-Linux"
#define AIK_UNPACK		AIK_BASE"/unpackimg.sh"
#define AIK_CLEANUP		AIK_BASE"/cleanup.sh"

#endif //__CYGWIN__ __APPLE__
// =====================================================================



#define VERSION_STRING "3.1.0"


// folders
#define OUT_MAIN				"OUT"
#define OUT_FIRMWARE			"firmware"
#define OUT_SYSTEM				"system"

#define TMP_ROMZIP				"romzip"
#define TMP_DUMPED_ZIPS			"dumped_zips"
#define TMP_DECRYPTED_ZIPS		"decrypted_zips"
#define TMP_DECRYPTED_SYSIMGS	"decrypted_system"


// Header MAGICs
#define HTC_LARGEZIP_HEADER_MAGIC	"LaR@eZip"
#define ZIP_HEADER_MAGIC			"PK\x03\x04"
#define HTC_ZIP_HEADER_MAGIC		"Htc@egi$"
#define SPARSE_MAGIC				"\x3a\xff\x26\xed"
#define BOOT_MAGIC					"ANDROID!"
#define IMAGE_DOS_SIGNATURE			"MZ"


// zip extraction inclusion / exclusion
#define SYSTEMIMG	"system*.img*"
#define BOOTIMG		"boot*.img"

// buffer size for keyfile
#define KEYFILE_SIZE 96


// MAX_EXEC_ARGS is the maximum number of arguments passed through exec() calls,
// needs to accommodate the max number of args when using run_program
// including the max system*.img* files
#define MAX_EXEC_ARGS 60


#define UNIX

#ifdef UNIX
	#define RED			"\033[0;31m"
	#define GREEN		"\033[0;32m"
	#define BLUE		"\033[0;34m"
	#define BLDUND		"\033[1;4m"  //bold underline
	#define NOCOLOR		"\033[0m"    //No Color

	#define SLASH	"/"
#else
	// i'm using cygwin for windows compile, so these don't really matter
	#define RED			"\033[0;31m"
	#define GREEN		"\033[0;32m"
	#define BLUE		"\033[0;34m"
	#define BLDUND		"\033[1;4m"  //bold underline
	#define NOCOLOR		"\033[0m"    //No Color

	#define SLASH	"\\"
#endif

// =====================================================================
// printf macros
// ---------------------------------------------------------------------
#define PRINT_INFO(format, ...)			printf(format "\n", ##__VA_ARGS__)

#define PRINT_TITLE(format, ...)		printf("\n\n" BLUE BLDUND format NOCOLOR "\n", ##__VA_ARGS__)
#define PRINT_PROGRESS(format, ...)		printf(BLUE format NOCOLOR "\n", ##__VA_ARGS__)
#define PRINT_ERROR(format, ...)		printf(RED "ERROR: " format NOCOLOR "\n", ##__VA_ARGS__)
#define PRINT_FINISHED(format, ...)		printf(BLUE "Finished: " format NOCOLOR "\n", ##__VA_ARGS__)
// =====================================================================


// used by --device DEVICE
#include "ruuveal/htc/devices.c"


// global variables
std::string full_path_to_maindir;
std::string full_path_to_keys;
std::string full_path_to_bins;
std::string full_path_to_wrk;

// needed for signal handling, so we dont loose tmp/romzip/rom.zip if it was a rom.zip on an abort
std::string signal_full_path_to_tmpzip;
std::string signal_full_path_to_ruu_zip;

// program flags
int keep_all_files = 0;
int do_immediate_cleanup = 1;
int create_system_only = 0;
int create_firmware_only = 0;
int create_sd_zip = 0;
int print_debug_info = 0;
std::string ruuveal_device;

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
int copy_file(const char *source, const char *destination, int skip = 0)
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

int copy_file(const std::string *source, const std::string *destination, int skip = 0)
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

int select_files_keyfiles(const struct dirent *de)
{
	std::string file_name = de->d_name;

	if (file_name.size() >= 4 && file_name.substr(file_name.size()-4) == ".bin")
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

int select_dirs(const struct dirent *de)
{
	if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
		return 0;
	else if (de->d_type == DT_DIR)
		return 1;
	else
		return 0;
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


int Check_If_New_Keyfile(const char *path_new_key_file, const char *full_path_keys)
{
	int exit_code = 1;
	int i;
	int num_of_keys;
	struct dirent **entry_list;

	FILE * pFile;
	char buffer_new_key[KEYFILE_SIZE];
	char buffer_chk_key[KEYFILE_SIZE];

	pFile = fopen(path_new_key_file, "rb" );
	if (pFile == NULL)
		exit_code = 3; // coulndt read new keyfile
	else {
		if (fread(buffer_new_key, 1, KEYFILE_SIZE, pFile) != KEYFILE_SIZE)
			exit_code = 4; // couldnt read new keyfile into buffer

		fclose(pFile);
	}

	std::string path_base = get_absolute_cwd();

	if (change_dir(full_path_keys))
		return 2;


	if (exit_code == 1) {
		num_of_keys = scandir(".", &entry_list, select_files_keyfiles, versionsort);
		if (is_scandir_error(entry_list, num_of_keys)) {
			exit_code = 5;
		}
		else {
			for (i = 0; i < num_of_keys; i++) {
				pFile = fopen(entry_list[i]->d_name, "rb" );
				if (pFile == NULL)
					exit_code = 6; // couldnt open file
				else {
					if (fread(buffer_chk_key, 1, KEYFILE_SIZE, pFile) != KEYFILE_SIZE)
						exit_code = 7; // couldnt read buffer
					else if (memcmp(buffer_new_key, buffer_chk_key, KEYFILE_SIZE) == 0)
							exit_code = 0; // key already exists

				fclose(pFile);
				}

				if (exit_code != 1)
					break;
			}
			free_dirent_entry_list(entry_list, num_of_keys);
		}
	}

	change_dir(path_base);

	return exit_code;
}


/*==============================================================================================================================
 * Attempt to find proper keyfile
 * -----------------------------
 *  This script will attempt to find a decryption key
 * 
 *  exit codes:
 *   -1 -> no encrypted zips (not an error, but decryption key necessary)
 *   0  -> successful
 *   1  -> usage
 *   2  -> path or file not found
 *   3  -> ruuveal, copy, unzip, or move failed to create destination files
 * 
 */

/*
 * Test_KeyFile
 * name: unknown
 * @param
 * @return
 * exit codes:
 *   0 -> passed all tests
 *   1 -> passed ruuveal
 *   2 -> passed ruuveal, but failed unzip
 */

int Test_KeyFile(const char *path_enczip, const char *path_keyfile)
{
	if (ruuveal_device.empty())
		PRINT_PROGRESS("Testing keyfile '%s'...", get_basename(path_keyfile));
	else
		PRINT_PROGRESS("Testing ruuveal device '%s'...", ruuveal_device.c_str());

	int res;
	int exit_code = 0;

	if (ruuveal_device.empty())
		res = run_program("ruuveal", "-K", path_keyfile, path_enczip, "tmpzip.zip", NULL);
	else
		res = run_program("ruuveal", "--device", ruuveal_device.c_str(), path_enczip, "tmpzip.zip", NULL);

	if (res == 0) {
		// PRINT_PROGRESS("keyfile passed ruuveal, running 2nd test...");

		res = run_program("unzip", "-t", "tmpzip.zip", NULL);

		if (res != 0) {
			// PRINT_PROGRESS("WARNING: keyfile did not create a proper zip (res=%i)!", res);
			exit_code = 2;
		}
	}
	else {
		// ruuveal couldnt decrypt using that key
		// PRINT_PROGRESS("WARNING: ruuveal failed (res=%i)!", res);
		exit_code = 1;
	}

	if (exit_code == 0) {
		PRINT_PROGRESS("INFO: keyfile passed all tests");
	}

	delete_file("tmpzip.zip");

	return exit_code;
}
/*==============================================================================================================================*/


/*==============================================================================================================================*/
std::string Find_First_Encrypted_ZIP(void)
{
	PRINT_PROGRESS("Find First Encrypted ZIP");

	int i;
	int num_of_zips;
	struct dirent **entry_list;
	std::string encrypted_zip;

	num_of_zips = scandir(".", &entry_list, select_files_zip, versionsort);
	if (is_scandir_error(entry_list, num_of_zips)) {
		return "ERROR-1";
	}

	for (i = 0; i < num_of_zips; i++) {
		char * file_name = entry_list[i]->d_name;

		if (access(file_name, R_OK) != 0) {
			PRINT_ERROR("Couldn't access '%s'", file_name);
		}
		else if (check_magic(file_name, 0x100, HTC_ZIP_HEADER_MAGIC) || check_magic(file_name, 0, HTC_ZIP_HEADER_MAGIC)) {
			encrypted_zip = file_name;
			PRINT_PROGRESS("Encrypted zip to be used for testing: '%s'", encrypted_zip.c_str());
			break;
		}
	}

	free_dirent_entry_list(entry_list, num_of_zips);

	return encrypted_zip;
}
/*==============================================================================================================================*/


/*==============================================================================================================================
 * Attempt to force generation of keyfile
 * ---------------------------------------
 *  find a decryption key using bruutveal
 * 
 *  exit codes:
 *    0  -> successful
 *    1  -> couldn't access provided hboot file (hboot / downloadzip from hosd)
 *    2  -> bruutveal was unsuccessful
 * 
 */
int Run_BRUUTVEAL(const char *path_hboot_file, const char *path_encrypted_zip_file, const char *path_output_key_file)
{
	int exit_code;
	int res;

	PRINT_INFO("");
	PRINT_PROGRESS("Attempting to generate keyfile");

	if (access(path_hboot_file, R_OK) != 0) {
		PRINT_ERROR("Couldn't access hboot file (%s)", path_hboot_file);
		exit_code = 1;
	}
	else {

		res = run_program("bruutveal", path_hboot_file, path_encrypted_zip_file, path_output_key_file, NULL);

		if (res == 0) {
			PRINT_PROGRESS("bruutveal keyfile has been successfully generated '%s'", path_output_key_file);
			exit_code = 0;
		}
		else {
			PRINT_ERROR("bruutveal was unable to generate keyfile (res=%i)", res);
			delete_file(path_output_key_file); // delete the file in case it was created (eg AIK-Windows)
			exit_code = 2;
		}
	}

	return exit_code;
}
/*==============================================================================================================================*/


/*==============================================================================================================================
 * Attempt to find proper keyfile
 * ------------------------------
 *  This script will attempt to find a decryption key
 * 
 *  exit codes:
 *   -1 -> no encrypted zips (not an error, but decryption key not necessary)
 *    0  -> successful
 *    1  -> usage
 *    2  -> path or file not found
 *    3  ->
 *    4  -> ruuveal, copy, unzip, or move failed to create destination files
 * 
 */
int KeyFinder_CheckInputFile(const char *full_path_encrypted_zip_file, const char *full_path_hboot_file, const char *full_path_output_key_file)
{
	// check if keyfile																			> test
	// check if hboot									-> then bruutveal using hboot			> test
	// check if hosd 		-> extract downloadzip 		-> then bruutveal using downloadzip		> test

	int exit_code = 1;
	int res;

	if (file_size(full_path_hboot_file) == 96) {
		PRINT_PROGRESS("... assuming keyfile, going to test it...");

		if (Test_KeyFile(full_path_encrypted_zip_file, full_path_hboot_file) == 0) {
			PRINT_PROGRESS("... the keyfile is good, copying it.");
			copy_file(full_path_hboot_file, full_path_output_key_file);
			exit_code = 0;
		}
		else {
			PRINT_ERROR("... the keyfile provided did not decrypt the zip properly!");
			exit_code = 2;
		}
	}
	else if (check_magic(full_path_hboot_file, 0, BOOT_MAGIC)) {
		PRINT_PROGRESS("... assuming hosd, going to unpack it...");


		// ALTERNATE METHOD NOT REQUIRING THE ENTIRE AIK
		// run unpack
		// run 7za
		// run bruutveal on ramdisk (dont even need to unpack it)

#if defined(__CYGWIN__)
		// no "reliable" method of invoking AIK by full path, in cygwin when both bin path and hosd path have spaces,
		// windows "cmd /C ..." would need double quotes, eg: cmd /C ""path with spaces to exe" "path to file with spaces""
		// which doesnt work, so temp copy the file to AIK and run (in most cases this should be writeable if it's not, fail)
		// maybe i should just get rid of it completely, and use the alternate method -_-
		if (win_path_has_spaces(full_path_to_bins.c_str()) && win_path_has_spaces(full_path_hboot_file)) {
			std::string aik_tmp_hosd = full_path_to_bins + "/" + AIK_BASE + "/" + "tmp_hosd";

			if (print_debug_info)
				printf("[DBG] the Tool path and the RUU path contain spaces; temporarily copy hosd file into the AIK folder\n\n");

			if (copy_file(full_path_hboot_file, aik_tmp_hosd.c_str()) != 0) {
				PRINT_ERROR("the Tool path and the RUU path contain spaces; temporarily copy hosd file into the AIK folder failed!");
				exit_code = 5;
			}
			else {
				res = run_program(AIK_UNPACK, "tmp_hosd", NULL);

				delete_file(aik_tmp_hosd.c_str());
			}
		}
		else // { // no brackets are needed since the next command is only one line, otherwise we'd need them!!
#endif  //__CYGWIN__

		res = run_program(AIK_UNPACK, full_path_hboot_file, NULL);

		if (res == 0) {
			std::string downloadzip = full_path_to_bins + "/" + AIK_BASE + "/ramdisk/sbin/downloadzip";
			if (access(downloadzip.c_str(), R_OK) == 0) {
				if (Run_BRUUTVEAL(downloadzip.c_str(), full_path_encrypted_zip_file, full_path_output_key_file) == 0) {
					exit_code = 0;
				}
			}
			else {
				PRINT_ERROR("hosd unpacked, but couldn't access downloadzip file");
				exit_code = 3;
			}
		}
		else {
			PRINT_ERROR("Unable to unpack hosd (res=%i)", res);
			exit_code = 4;
		}

		run_program(AIK_CLEANUP, NULL);
	}
	else {
		PRINT_PROGRESS("... assuming hboot...");
		if (Run_BRUUTVEAL(full_path_hboot_file, full_path_encrypted_zip_file, full_path_output_key_file) == 0) {
			exit_code = 0;
		}
	}

	// if (foundkey) should we double check that key by testing it?

	return exit_code;
}

int KeyFinder_CheckKeyfilesFolder(const char *full_path_encrypted_zip_file, const char *full_path_keys, const char *full_path_output_key_file)
{
	PRINT_INFO("");
	PRINT_PROGRESS("No proper keyfile, trying known keys instead...");

	int exit_code = 1;
	int res;
	int i;
	int num_of_keys;
	struct dirent **entry_list;

	num_of_keys = scandir(full_path_keys, &entry_list, select_files_keyfiles, versionsort);
	if (is_scandir_error(entry_list, num_of_keys)) {
		exit_code = 2;
	}
	else {
		for (i = 0; i < num_of_keys; i++) {
			char * keyfile = entry_list[i]->d_name;
			std::string full_path_key_file = (std::string) full_path_keys + "/" + keyfile;

			if (Test_KeyFile(full_path_encrypted_zip_file, full_path_key_file.c_str()) == 0) {
				exit_code = 0;
				if ((res = copy_file(full_path_key_file.c_str(), full_path_output_key_file)) != 0) {
					PRINT_ERROR("Found keyfile '%s', but couldn't copy it (res=%i)", full_path_key_file.c_str(), res);
					exit_code = 3;
				}
				break;
			}
		}
		free_dirent_entry_list(entry_list, num_of_keys);
	}

	return exit_code;
}

int KeyFinder_CheckRuuvealKeys(const char *full_path_encrypted_zip_file)
{
	int exit_code = 1;

	PRINT_INFO("");
	PRINT_INFO("");
	PRINT_PROGRESS("Still no proper keyfile, trying all ruuveal built-in keys...");

	htc_device_t *ptr;

	for(ptr = htc_get_devices(); *ptr->name; ptr++) {
		ruuveal_device = ptr->name;

		if (Test_KeyFile(full_path_encrypted_zip_file, NULL) == 0) {
			exit_code = 0;
			break;
		}
	}

	if (exit_code != 0)
		ruuveal_device.clear();

	return exit_code;
}

int KeyFinder_TryForceExtraction(const char *full_path_encrypted_zip_file, const char *full_path_output_key_file)
{
	PRINT_INFO("");
	PRINT_PROGRESS("Trying force extraction of hboot/hosd...");

	int exit_code = 1;
	int i;
	int num_of_zips;
	int num_of_files;
	struct dirent **entry_list;

	std::string path_base = get_absolute_cwd();

	mkdir("tmp", 0777);

	// try to extract hboot or hosd
	num_of_zips = scandir(".", &entry_list, select_files_zip, versionsort);
	if (is_scandir_error(entry_list, num_of_zips)) {
		exit_code = 2;
	}
	else {
		for (i = 0; i < num_of_zips; i++) {
			char * zip_file = entry_list[i]->d_name;

			// disregard any errors
			run_program("unzip", "-n", zip_file, "hboot*", "hosd*", "-d", "tmp", NULL);

		}
		free_dirent_entry_list(entry_list, num_of_zips);
	}

	// if we did get files, let's try them out
	num_of_files = scandir("tmp", &entry_list, select_files_any, versionsort);
	if (num_of_files < 0) {
		PRINT_ERROR("scandir error");
		exit_code = 3;
	}
	else if (num_of_files > 0) {
		for (i = 0; i < num_of_files; i++) {
			std::string full_path_test_file = path_base + "/" + "tmp" + "/" + entry_list[i]->d_name;

			if (KeyFinder_CheckInputFile(full_path_encrypted_zip_file, full_path_test_file.c_str(), full_path_output_key_file) == 0) {
				exit_code = 0; // yay
			}
		}
		free_dirent_entry_list(entry_list, num_of_files);
	}
	else {
		PRINT_PROGRESS("no files were force-extracted.");
	}

	delete_dir_contents("tmp");
	remove("tmp");

	return exit_code;
}


int KeyFinder(const char *path_inp_enczipfiles, const char *full_path_keys, const char *full_path_hboot_file, const char *path_out_key_file)
{
	PRINT_TITLE("Attempting to find suitable keyfile");

	std::string path_base = get_absolute_cwd();
	std::string full_path_output_key_file = path_base + "/" + path_out_key_file;

	//we need to operate in the encrypted zips folder
	if (change_dir(path_inp_enczipfiles))
		return 2;

	std::string encrypted_zip = Find_First_Encrypted_ZIP();
	if (encrypted_zip == "ERROR-1") {
		PRINT_ERROR("Couldn't access files");
		change_dir(path_base);
		return 2;
	}
	else if (encrypted_zip.empty()) {
		PRINT_FINISHED("No encrypted zip(s) found, keyfile not needed");
		//echo "no_key_needed" >"$output_keyfile"
		change_dir(path_base);
		return -1;
	}


	int exit_code = 0;
	int res;

	std::string full_path_encrypted_zip_file = path_base + "/" + path_inp_enczipfiles + "/" + encrypted_zip;
	//PRINT_PROGRESS("Encrypted zip to be used for testing: '%s'", full_path_encrypted_zip_file.c_str());


	int is_user_supplied = (full_path_hboot_file != NULL) && full_path_hboot_file[0] != '\x00';

	int foundkey = 0;

	if (!foundkey && is_user_supplied && (file_size(full_path_hboot_file) == 96)) {
		PRINT_INFO("");
		PRINT_PROGRESS("User supplied keyfile, going to test...");
		res = KeyFinder_CheckInputFile(full_path_encrypted_zip_file.c_str(), full_path_hboot_file, full_path_output_key_file.c_str());
		if (res == 0)
			foundkey = 1;
		else if (res > 1)
			PRINT_ERROR("in function CheckInputFile (res=%i)", res);
	}

	if (!foundkey && !ruuveal_device.empty()) {
		PRINT_PROGRESS("--device '%s' specified, testing...", ruuveal_device.c_str());

		if (Test_KeyFile(full_path_encrypted_zip_file.c_str(), NULL) == 0) {
			foundkey = 1;
		}
	}

	// if we still don't have a key, try all known keys
	if (!foundkey) {
		res = KeyFinder_CheckKeyfilesFolder(full_path_encrypted_zip_file.c_str(), full_path_keys, full_path_output_key_file.c_str());
		if (res == 0)
			foundkey = 1;
		else if (res > 1)
			PRINT_ERROR("in function CheckKeyfilesFolder (res=%i)", res);
	}

	// if we still don't have a key, try all ruuveal device keys
	if (!foundkey) {
		// if it's found then ruuveal_device will be updated
		res = KeyFinder_CheckRuuvealKeys(full_path_encrypted_zip_file.c_str());
		if (res == 0)
			foundkey = 1;
		else if (res > 1)
			PRINT_ERROR("in function CheckRuuvealKeys (res=%i)", res);
	}

	// bruutveal can be slow, so let's move it down here
	if (!foundkey && is_user_supplied) {
		PRINT_INFO("");
		PRINT_PROGRESS("User supplied hboot / hosd, going to generate...");
		res = KeyFinder_CheckInputFile(full_path_encrypted_zip_file.c_str(), full_path_hboot_file, full_path_output_key_file.c_str());
		if (res == 0)
			foundkey = 1;
		else if (res > 1)
			PRINT_ERROR("in function CheckInputFile (res=%i)", res);
	}

	if (!foundkey) {
		// try forcing extraction of hboot or hosd
		// this is a longshot and will likely not work, except for the RUUs that have the first zip signed but not encrypted
		res = KeyFinder_TryForceExtraction(full_path_encrypted_zip_file.c_str(), full_path_output_key_file.c_str());
		if (res == 0)
			foundkey = 1;
		else if (res > 1)
			PRINT_ERROR("in function TryForceExtraction (res=%i)", res);
	}

	if (!foundkey || exit_code) {
		PRINT_INFO("");
		PRINT_INFO("");
		PRINT_INFO("");
		PRINT_ERROR("Could not find suitable decryption key!\n\nPlease provide a suitable keyfile, hboot or hosd (depending on device).");
		PRINT_INFO("");
		exit_code = 4;
	}
	else if (!ruuveal_device.empty()) {
		PRINT_FINISHED("Successfully found decryption key, ruuveal device '%s'", ruuveal_device.c_str());
		exit_code = 0;
	}
	else {
		PRINT_FINISHED("Successfully found decryption key, copied to '%s'", path_out_key_file);
		exit_code = 0;
	}

	change_dir(path_base);

	return exit_code;
}
/*==============================================================================================================================*/


/*==============================================================================================================================
 * Create the system.img file
 * -----------------------------
 * usage: CreateSystemIMG.sh <input_path> <output_path> [-C|--cleanup]
 *    -C flag -> if successfull do cleanup; ie remove system files from input path
 *               and remove the input path if possible
 * 
 *    in input_path it will look for
 *       * system.img (single file)
 *       * system?*.img (multi-part, similar to newer M7)
 *       * system.img?* (multi-part, similar to newer M9)
 *       multi-part files will be checked if sparse
 *         -> if yes, then simg2img
 *         -> otherwise concatenate
 * ->> finally test system.img using e2fsck
 * 
 * exit codes:
 *   0 -> successful
 *   1 -> usage
 *   2 -> path or file not found
 *   3 ->
 *   4 -> mv, simg2img, or cat failed to create system.img
 *   5 -> system.img did not pass e2fsck check
 * 
 */
int CreateSystemIMG(const char *path_inp_sysimgfiles, const char *path_output_system_img_file)
{
	PRINT_TITLE("Attempting to create '%s'", path_output_system_img_file);

	std::string path_base = get_absolute_cwd();
	std::string full_path_output_system_img_file = path_base + "/" + path_output_system_img_file;

	// we need to operate in the system.img folder folder
	if (change_dir(path_inp_sysimgfiles))
		return 2;


	int exit_code = 0;
	int res;
	int i;
	int num_of_imgs;
	struct dirent **entry_list;

	num_of_imgs = scandir(".", &entry_list, select_files_systemimg, versionsort);
	if (is_scandir_error(entry_list, num_of_imgs))
		return 2;

	remove(full_path_output_system_img_file.c_str());

	if (num_of_imgs == 1) {
		char * file_name = entry_list[0]->d_name;
		// Simple system.img
		PRINT_PROGRESS("Single '%s' found, moving it to output path", path_output_system_img_file);
		if ((res = move_file(file_name, full_path_output_system_img_file.c_str()))) {
			PRINT_ERROR("could not create system.img (err=%i)", res);
			exit_code = 3;
		}
	}
	else {
		PRINT_PROGRESS("Multi-part system images (%i parts)", num_of_imgs);

		char * file_name = entry_list[0]->d_name;

		if (access(file_name, R_OK)) {
			PRINT_ERROR("Couldn't access '%s'", file_name);
			exit_code = 3;
		}

		else if (check_magic(file_name, 0, SPARSE_MAGIC)) {
			PRINT_PROGRESS("Sparse Image detected, using simg2img");
			PRINT_PROGRESS("    Please be patient, this can take several minutes...");

			// wildcards arent allowed in run_program
			char * args[MAX_EXEC_ARGS];
			for (i = 0; i < num_of_imgs; i++)
				args[i] = entry_list[i]->d_name;
			args[i] = (char *)full_path_output_system_img_file.c_str();
			args[i+1] = NULL;
			res = run_program("simg2img", args);

			if (res != 0) {
				PRINT_ERROR("could not create '%s' (err=%i)", path_output_system_img_file, res);
				exit_code = 4;
			} else
				PRINT_PROGRESS("finished.");
		}

		else {
			PRINT_PROGRESS("Sparse Header not found, using simple concatenate");
			PRINT_PROGRESS("    Please be patient, this can take several minutes...");
			for (i = 0; i < num_of_imgs; i++) {
				file_name = entry_list[i]->d_name;
				PRINT_PROGRESS("    (%i/%i) %s -> '%s'", i+1, num_of_imgs, file_name, path_output_system_img_file);
				exit_code = append_file(file_name, full_path_output_system_img_file.c_str());

				if (exit_code == 0 && do_immediate_cleanup) {
					PRINT_PROGRESS("    ... immediate cleanup specified, deleting '%s'", file_name);
					delete_file(file_name);
				}

			}
			PRINT_PROGRESS("finished.");
		}
	}

	free_dirent_entry_list(entry_list, num_of_imgs);

	if (exit_code == 0)
		PRINT_FINISHED("Successfully created '%s'", path_output_system_img_file);

	change_dir(path_base);

	return exit_code;
}
/*==============================================================================================================================*/


/*==============================================================================================================================*/
int TestSystemIMG(const char *path_systemimg_file)
{
	PRINT_TITLE("Testing '%s'...", path_systemimg_file);

	int res;
	int exit_code = 0;

	res = run_program("e2fsck", "-fn", path_systemimg_file, NULL);

	if (res != 0) {
		PRINT_ERROR("'%s' is corrupt (err=%i)", path_systemimg_file, res);
		//delete_file("path_out/system.img");
		//rmdir("$path_out");
		exit_code = 5;
	}

	/*
	#we can add these later (add flags to the arguments),
	#but the mount commands requires sudo
	#----------------------------------------------------
	#mkdir "$path_out/sysmount"
	#mount -o ro "$path_out/system.img" "$path_out/sysmount"
	#cp "$path_out/sysmount/build.prop" "$path_out/build.prop"
	#ls -lAR "$path_out/sysmount" > "$path_out/system_listing.txt"
	#umount "$path_out/sysmount"
	#rmdir "$path_out/sysmount"
	*/

	if (exit_code == 0)
		PRINT_FINISHED("'%s' successfully passed filesystem check", path_systemimg_file);

	return exit_code;
}
/*==============================================================================================================================*/



/*==============================================================================================================================
 * Decrypt/unzip individual zips
 * -----------------------------
 *  This script will decrypt the individual zips (if needed)
 *  then unzip and move as necessary to
 *    unencrypted zips to      -> $path_out/decrypted_zips
 *    all RUU files to         -> $path_out/decrypted_all
 *    move system img files to -> $path_out/decrypted_system
 * 
 *  usage: DecryptZIPs.sh <input_path> <output_path> <keyfile> [-C|--cleanup]
 *    -C flag -> if successfull do cleanup; ie just remove the decrypted_zips
 * 
 *  exit codes:
 *   0 -> successful
 *   1 -> usage
 *   2 -> path or file not found
 *   3 ->
 *   4 -> ruuveal, copy, unzip, or move failed to create destination files
 */
int DecryptZIPs(const char *path_inp_dumpedzips, const char *path_out_decryptedzips, const char *path_key_file)
{
	PRINT_TITLE("Decrypting ZIP files");

	int exit_code = 0;
	int res;
	int i;
	int num_of_zips;
	struct dirent **entry_list;

	std::string path_base = get_absolute_cwd();
	std::string full_path_out_decryptedzips = path_base + "/" + path_out_decryptedzips;
	std::string full_path_key_file; if (path_key_file) full_path_key_file = path_base + "/" + path_key_file;

	// we need to operate in the dumpedzips folder
	if (change_dir(path_inp_dumpedzips))
		return 2;


	num_of_zips = scandir(".", &entry_list, select_files_zip, versionsort);
	if (is_scandir_error(entry_list, num_of_zips)) {
		exit_code = 2;
	}

	else {
		// begin processing zips
		for (i = 0; i < num_of_zips; i++) {
			// possible file formats:
			//   1- signed & encrypted
			//   2- encrypted but not signed
			//   3- signed but not encrypted
			//   4- neither signed nor encrypted
			char * file_name = entry_list[i]->d_name;

			PRINT_PROGRESS("\nDecrypting (%i/%i) '%s'", i+1, num_of_zips, file_name);

			if (access(file_name, R_OK)) {
				PRINT_ERROR("Couldn't access '%s'", file_name);
				exit_code = 3;
			}

			else if ((!full_path_key_file.empty()) && (check_magic(file_name, 0x100, HTC_ZIP_HEADER_MAGIC) || check_magic(file_name, 0, HTC_ZIP_HEADER_MAGIC))) {
				// Htc@egi$ encrypted file
				// 1- signed & encrypted
				// 2- encrypted but not signed
				PRINT_PROGRESS("Encrypted zip detected, running ruuveal...");

				if (ruuveal_device.empty())
					res = run_program("ruuveal", "-K", full_path_key_file.c_str(), file_name, (full_path_out_decryptedzips + "/" + "dec_" + file_name).c_str(), NULL);
				else
					res = run_program("ruuveal", "--device", ruuveal_device.c_str(), file_name, (full_path_out_decryptedzips + "/" + "dec_" + file_name).c_str(), NULL);

				if (res != 0) {
					PRINT_ERROR("could not decrypt file '%s' (res=%i)", file_name, res);
					exit_code = 4;
				}
			}

			else {
				// assume non encrypted zip, test and if OK copy it
				PRINT_PROGRESS("Encryption not found, checking headers...");

				if (check_magic(file_name, 0x100, ZIP_HEADER_MAGIC)) {
					// 3- signed but not encrypted
					// signed zip, so get rid of the signature to avoid unzip warnings
					// (we could just allow exit code 1 [non fatal warning], but better to just get rid of the signature, and test
					PRINT_PROGRESS("    signed zip, removing signature, copying, then testing...");
					std::string output_file = full_path_out_decryptedzips + "/" + "dec_" + file_name;
					if ((res = copy_file(file_name, output_file.c_str(), 256))) {
						PRINT_ERROR("could not copy unencrypted zip to destination (err=$%i)", res);
						exit_code = 4;
					}
					else {

						res = run_program("unzip", "-q", "-t", output_file.c_str(), NULL);

						if (res != 0) {
							PRINT_ERROR("unencrypted+unsigned zip failed test (err=%i)", res);
							//rm "$path_out/decrypted_zips/dec_$i"
							exit_code = 4;
						}
						else
							PRINT_PROGRESS("unzip test OK...");
					}
				}

				else if (check_magic(file_name, 0, ZIP_HEADER_MAGIC)) {
					// 4- neither signed nor encrypted
					// normal zip, no signature
					PRINT_PROGRESS("    normal zip, testing...");

					res = run_program("unzip", "-q", "-t", file_name, NULL);

					if (res != 0) {
						PRINT_ERROR("unencrypted zip failed test (err=%i)", res);
						exit_code = 4;
					}
					else {
						PRINT_PROGRESS("unzip test OK, copying file...");
						std::string output_file = full_path_out_decryptedzips + "/" + "dec_" + file_name;
						if ((res = copy_file(file_name, output_file.c_str()))) {
							PRINT_ERROR("could not copy unencrypted zip to destination (err=$%i)", res);
							exit_code = 4;
						}
					}
				}

				else {
					PRINT_ERROR("could not identify file type, aborting");
					exit_code = 4;
				}
			}

			if (exit_code == 0 && do_immediate_cleanup) {
				PRINT_PROGRESS("... immediate cleanup specified, deleting '%s'", file_name);
				delete_file(file_name);
			}

		}
	}

	free_dirent_entry_list(entry_list, num_of_zips);

	change_dir(path_base);

	if (exit_code == 0)
		PRINT_FINISHED("Successfully decrypted zips to '%s'", path_out_decryptedzips);

	return exit_code;
}
/*==============================================================================================================================*/


/*==============================================================================================================================
 * Unzip decrypted zip files to independent folders
 * ------------------------------------------------
 *
 * exit codes:
 *   0 -> successful
 *   1 -> usage
 *   2 -> path or file not found
 *   3 -> 
 *   4 -> ruuveal, unzip, or copy failed to create destination files
 */
int UnzipDecryptedZIPs(const char *path_inp_zips, const char *path_outfiles)
{
	PRINT_TITLE("Unzipping decrypted ZIP files");

	std::string path_base = get_absolute_cwd();
	std::string full_path_to_outfiles = path_base + "/" + path_outfiles;

	// operate in the zips folder
	if (change_dir(path_inp_zips))
		return 2;


	int exit_code = 0;
	int res;
	int i;
	int num_of_zips;
	struct dirent **entry_list;

	// unzip all zip files to decrypted_all
	num_of_zips = scandir(".", &entry_list, select_files_zip, versionsort);
	if (is_scandir_error(entry_list, num_of_zips)) {
		PRINT_ERROR("No zip files found!");
		exit_code = 2;
	}
	else {
		for (i = 0; i < num_of_zips; i++) {
			char * file_name = entry_list[i]->d_name;

			PRINT_PROGRESS("\nUnzipping decrypted zip: (%i/%i) '%s'", i+1, num_of_zips, file_name);

			if (create_system_only)
				res = run_program("unzip", "-n", file_name, SYSTEMIMG, BOOTIMG, "-d", full_path_to_outfiles.c_str(), NULL);
			else if (create_firmware_only)
				res = run_program("unzip", "-n", file_name, "-x", SYSTEMIMG, "-d", full_path_to_outfiles.c_str(), NULL);
			else
				res = run_program("unzip", "-n", file_name, "-d", full_path_to_outfiles.c_str(), NULL);

			// also disregard error 11 (no matched files, due to inclusion or exclusion)
			if (res != 0 && res != 11) {
				PRINT_ERROR("could not unzip file (res=%i)", res);
				exit_code = 3;
			}

			if (exit_code == 0 && do_immediate_cleanup) {
				PRINT_PROGRESS("... immediate cleanup specified, deleting '%s'", file_name);
				delete_file(file_name);
			}
		}
		free_dirent_entry_list(entry_list, num_of_zips);
	}

	change_dir(path_base);

	if (exit_code == 0)
		PRINT_FINISHED("Successfully unzipped files to '%s'", path_outfiles);

	return exit_code;
}
/*==============================================================================================================================*/


/*==============================================================================================================================
 * Move system img files
 * ------------------------------------------------
 *
 * exit codes:
 *   0 -> successful
 *   1 -> usage
 *   2 -> path or file not found
 *   3 -> 
 *   4 -> ruuveal, unzip, or copy failed to create destination files
 */
int MoveSystemIMGFiles(const char *path_inp_files, const char *path_outsystemimgs)
{
	PRINT_TITLE("Moving system img files");

	std::string path_base = get_absolute_cwd();
	std::string full_path_to_outsystemimgs = path_base + "/" + path_outsystemimgs;
	std::string base_system_name;
	std::size_t found;

	// operate in the files folder
	if (change_dir(path_inp_files))
		return 2;

	int exit_code = 0;
	int res;
	int i;
	int num_of_imgs;
	struct dirent **entry_list;

	num_of_imgs = scandir(".", &entry_list, select_files_systemimg, versionsort);
	if (is_scandir_error(entry_list, num_of_imgs)) {
		exit_code = 2;
	}
	else {
		// PRINT_PROGRESS("Move %i system img files to system folder...", num_of_imgs);
		for (i = 0; i < num_of_imgs; i++) {
			char * file_name = entry_list[i]->d_name;
			base_system_name = file_name;

			found = base_system_name.rfind(".img");								// remove everything from and including .img
			if (found != std::string::npos) base_system_name.erase(found);

			found = base_system_name.find_last_not_of("0123456789");			// remove any trailing numerical chars (multi part img file)
			if (found != std::string::npos) base_system_name.erase(found+1);

			found = base_system_name.find_last_not_of("_");						// remove any other trailing chars we don't want
			if (found != std::string::npos) base_system_name.erase(found+1);
			//OR: if (base_system_name.back() == '_') base_system_name.pop_back();	// remove single trailing '_' (this needs c++11, so compile with -std=gnu++11)


			full_path_to_outsystemimgs = path_base + "/" + path_outsystemimgs + "/" + base_system_name;

			mkdir(full_path_to_outsystemimgs.c_str(), 0777);

			PRINT_PROGRESS("   (%i/%i) moving %s to %s", i+1, num_of_imgs, file_name, base_system_name.c_str());
			if ((res = move_file(file_name, ".", full_path_to_outsystemimgs.c_str())) != 0) {
				PRINT_ERROR("could not move system img file (res=%i)", res);
				exit_code = 3;
			}
		}
		free_dirent_entry_list(entry_list, num_of_imgs);
	}

	change_dir(path_base);

	if (exit_code == 0)
		PRINT_FINISHED("Successfully moved system img files");


	return exit_code;
}
/*==============================================================================================================================*/


/*==============================================================================================================================
 * Extract individual zips
 * -----------------------------
 * This script will extract the individual zips, if needed from
 *     1- single zip -> not needed
 *     2- LaR@eZip -> ruuveal -D (M7, M8, M9, etc style)
 *     3- normal zip containing multiple zip archives -> unzip (A9 style)
 * (we'll deal with encryption later)
 *
 * usage: ExtractZIPs.sh <input_path> <output_path> <RUUzipName> [-C|--cleanup]
 *   -C flag -> if successful do cleanup; ie delete rom.zip from input path
 *              and remove the input path if possible
 *   RUUzipName has to end with zip extension (case insensitive)
 *
 * exit codes:
 *   0 -> successful
 *   1 -> usage
 *   2 -> path or file not found
 *   3 -> 
 *   4 -> ruuveal, unzip, or copy failed to create destination files
 */
int ExtractZIPs(const char *path_to_ruu_file, const char *path_out)
{
	PRINT_TITLE("Extracting ZIP files");

	int res;
	int exit_code = 0;

	std::string path_base = get_absolute_cwd();
	std::string full_path_to_ruu_file = path_base + "/" + path_to_ruu_file;


	// ruuveal needs to operate in output folder
	if (change_dir(path_out))
		return 2;


	// check file access
	if (access(full_path_to_ruu_file.c_str(), F_OK | R_OK)) {
		PRINT_ERROR("Couldn't access '%s'", path_to_ruu_file);
		exit_code = 3;
	}


	// begin checking headers
	else if (check_magic(full_path_to_ruu_file.c_str(), 0, HTC_LARGEZIP_HEADER_MAGIC)) {
		// LargeZip Header
		PRINT_PROGRESS("LargeZip format detected, using ruuveal");

		res = run_program("ruuveal", "-D", full_path_to_ruu_file.c_str(), "dmp.zip", NULL);

		if (res != 0) {
			PRINT_ERROR("ruuveal returned error, aborting (err=%i)", res);
			exit_code = 4;
		}
	}

	else if (check_magic(full_path_to_ruu_file.c_str(), 0, ZIP_HEADER_MAGIC)) {
		// zip Header
		// possible TODO: check if that zip is actually an RUU, not just a regular zip
		PRINT_PROGRESS("Normal Zip format detected, using unzip");

		res = run_program("unzip", full_path_to_ruu_file.c_str(), NULL);

		if (res != 0) {
			PRINT_ERROR("unzip returned error, aborting (err=%i)", res);
			exit_code = 4;
		}
	}

	else {
		// assuming single file zip (HTC signed)
		// TODO: note: there could be a rom_01.zip and rom_02.zip (rom_02 contains an extractable hboot)
		//   (eg RUU_JEWEL_CL_JB_45_S_Sprint_WWE_3.15.651.16_Radio_1.12.11.1119_NV_2.87_003_25007_release_299302_signed.exe)
		// something similar with one of the TmoUS M7 RUUs, can't remember which though, have to check TODO
		PRINT_PROGRESS("Normal file detected, just copy it");
		if ((res = copy_file(full_path_to_ruu_file.c_str(), "unchanged.zip")) != 0) {
			PRINT_ERROR("copy failed, aborting (err=%i)", res);
			exit_code = 4;
		}
	}


	if (exit_code == 0)
		PRINT_FINISHED("Successfully extracted zip files to '%s'", path_out);

	change_dir(path_base);

	return exit_code;
}
/*==============================================================================================================================*/


/*==============================================================================================================================*/
struct android_info {
	std::string modelid;
	std::string mainver;
};

android_info Parse_Android_Info(const char *path_android_info_file)
{
	android_info info;
	std::string line;
	std::ifstream infile(path_android_info_file);

	while (std::getline(infile, line)) {
		if (info.modelid.empty() && line.compare(0, 9, "modelid: ") == 0)
			info.modelid = line.substr(9);
		else if (info.mainver.empty() && line.compare(0, 9, "mainver: ") == 0)
			info.mainver = line.substr(9);
	}

	infile.close();

	return info;
}
/*==============================================================================================================================*/


/*==============================================================================================================================*/
int UnRUU(const char *path_ruu_exe_name, const char *path_out)
{
	PRINT_TITLE("Extracting rom.zip from %s", get_basename(path_ruu_exe_name));

	std::string path_base = get_absolute_cwd();

	// we need to operate in the out folder since unruu only outputs to current
	if (change_dir(path_out))
		return 2;

	int exit_code = 0;
	int res;

	res = run_program("unruu", path_ruu_exe_name, NULL);

	if (res != 0) {
		PRINT_ERROR("UnRUU failed");
		exit_code = 4;
	}

// TODO: check the files we got and rename accordingly 

	change_dir(path_base);

	return exit_code;
}
/*==============================================================================================================================*/


/*==============================================================================================================================*/
// interrupt handler in case we need to move the original rom.zip back to origin
void signal_Handler(int sig_num)
{
	printf("\n\nE-SIGNAL received signal=%i, try moving back rom.zip to origin and exit\n\n", sig_num);
	rename(signal_full_path_to_tmpzip.c_str(), signal_full_path_to_ruu_zip.c_str());
	exit(sig_num);
}
/*==============================================================================================================================*/

/*==============================================================================================================================*/
int main(int argc, char **argv)
{
	PRINT_TITLE("+++ Welcome to the HTC RUU Decryption Tool %s +++", VERSION_STRING);
	PRINT_INFO ("        by  nkk71  and  Captain_Throwback        ");
	PRINT_INFO ("          Mac OS X support by topjohnwu          ");
	PRINT_INFO("");

	int exit_code = 0;
	int is_exe;


	// parse arguments
	std::string path_cur = get_absolute_cwd();
	std::string cmd_name = argv[0];

	std::string path_ruuname;
	std::string path_hb;

	argc--;
	argv++;
	while(argc > 0) {
		char *arg = argv[0];

		argc -= 1;
		argv += 1;

		if (!strcmp(arg, "--keepall") || !strcmp(arg, "-k")) {
			keep_all_files = 1;
			do_immediate_cleanup = 0;
		}
		else if (!strcmp(arg, "--slowcleanup") || !strcmp(arg, "-c")) {
			keep_all_files = 0;
			do_immediate_cleanup = 0;
		}
		else if (!strcmp(arg, "--systemonly") || !strcmp(arg, "-s")) {
			create_system_only = 1;
		}
		else if (!strcmp(arg, "--firmwareonly") || !strcmp(arg, "-f")) {
			create_firmware_only = 1;
		}
		else if (!strcmp(arg, "--sdruuzip") || !strcmp(arg, "-z")) {
			create_sd_zip = 1;
		}
		else if (!strcmp(arg, "--debuginfo") || !strcmp(arg, "-P")) {
			print_debug_info = 1;
		}
		else if (!strcmp(arg, "--device") || !strcmp(arg, "-d")) {
			if (argc > 0) {
				ruuveal_device = argv[0];
				argc -= 1;
				argv += 1;
			}
			else {
				PRINT_ERROR("No DEVICE parameter specified for --device DEVICE option.");
				return 1;
			}

			int supported = 0;
			htc_device_t *ptr;

			for(ptr = htc_get_devices(); *ptr->name; ptr++) {
				if (ruuveal_device == ptr->name) {
					supported = 1;
					break;
				}
			}

			if (!supported) {
				PRINT_ERROR("Incorrect parameter for --device: '%s' is not supported.", ruuveal_device.c_str());
				printf("supported devices:-\n\n");
				for(ptr = htc_get_devices(); *ptr->name; ptr++) {
					printf("* %s (%s)\n", ptr->desc, ptr->name);
				}
				printf("\n");
				return 1;
			}
		}
		else if (path_ruuname.empty()) {
			path_ruuname = arg;
		}
		else if (!path_ruuname.empty()) {
			path_hb = arg;
		}
	}

	if (path_ruuname.empty()) {
		PRINT_INFO("");
		PRINT_INFO("Usage:%s [options] <RUUName: RUU.exe or ROM.zip> [keyfile/hboot/hosd]", cmd_name.c_str());
		PRINT_INFO("");
		PRINT_INFO("   Optional arguments");
		PRINT_INFO("      -s, --systemonly     only extract the system.img and boot.img (for ROM)");
		PRINT_INFO("      -f, --firmwareonly   only extract the firmware files (exclude system.img)");
		PRINT_INFO("      -z, --sdruuzip       also copy and rename rom.zip for SD-Card flashing");
		PRINT_INFO("                           Note: this will create a duplicate if the input is already a rom.zip");
		PRINT_INFO("");
		PRINT_INFO("   Debugging Options (not usually needed)");
		PRINT_INFO("      -k, --keepall        keep all intermediary files");
		PRINT_INFO("      -c, --slowcleanup    do a 'slow cleanup', ie dont delete files once partially processed");
		PRINT_INFO("      -P, --debuginfo      print debug info (paths and exec)");
		PRINT_INFO("");
		PRINT_INFO("   Direct ruuveal support (needed for older devices)");
		PRINT_INFO("      -d, --device DEVICE  specify device (this is only needed for old unruu supported devices)");
		PRINT_INFO("                           please run unruu to see the list of DEVICEs supported");
		PRINT_INFO("");
		PRINT_INFO("");
		return 1;
	}

	if ((create_system_only && create_firmware_only)) {
		PRINT_INFO("");
		PRINT_INFO("Usage Info: you have specified both -s and -f, this is the default behaviour");
		PRINT_INFO("            and doesn't need to be specified it's either -s or -f, so both will");
		PRINT_INFO("            be created in this case too.");
		PRINT_INFO("");
		create_system_only = 0;
		create_firmware_only = 0;
	}

	std::string full_path_to_ruu_file;
	std::string full_path_to_hb_file;
	{
		char tmp_filename_buffer[PATH_MAX];

		if (realpath(path_ruuname.c_str(), tmp_filename_buffer) == NULL) {
			PRINT_ERROR("Couldn't resolve full path to file '%s'!", path_ruuname.c_str());
			return 2;
		}
		else
			full_path_to_ruu_file = convert_to_absolute_path(tmp_filename_buffer);


		if (!path_hb.empty()) {
			if (realpath(path_hb.c_str(), tmp_filename_buffer) == NULL) {
				PRINT_ERROR("Couldn't resolve full path to file '%s'!", path_hb.c_str());
				return 2;
			}
			else
				full_path_to_hb_file = convert_to_absolute_path(tmp_filename_buffer);
		}
	}

	is_exe = 0;
	if (access(full_path_to_ruu_file.c_str(), R_OK)) {
		PRINT_ERROR("Couldn't read file '%s'!", full_path_to_ruu_file.c_str());
		return 2;
	}
	else if (check_magic(full_path_to_ruu_file.c_str(), 0, IMAGE_DOS_SIGNATURE)) {
		PRINT_PROGRESS("RUU identified as Executable file");
		is_exe = 1;
	}
	else if (check_magic(full_path_to_ruu_file.c_str(), 0, HTC_LARGEZIP_HEADER_MAGIC))		// LargeZip
		PRINT_PROGRESS("RUU identified as HTC LargeZip file");
	else if (check_magic(full_path_to_ruu_file.c_str(),   0, ZIP_HEADER_MAGIC))				// Normal zip
		PRINT_PROGRESS("RUU identified as Normal Zip file");
	else if (check_magic(full_path_to_ruu_file.c_str(), 256, ZIP_HEADER_MAGIC))				// Normal zip + signed
		PRINT_PROGRESS("RUU identified as Normal Signed Zip file");
	else if (check_magic(full_path_to_ruu_file.c_str(),   0, HTC_ZIP_HEADER_MAGIC))			// HTC Encrypted zip
		PRINT_PROGRESS("RUU identified as HTC Encrypted Zip file");
	else if (check_magic(full_path_to_ruu_file.c_str(), 256, HTC_ZIP_HEADER_MAGIC))			// HTC Encrypted zip + signed
		PRINT_PROGRESS("RUU identified as HTC Singed Encrypted Zip file");
	else {
		PRINT_ERROR("Couldn't identify '%s' file format!", path_ruuname.c_str());
		return 2;
	}

	// setup global paths
	{
#if defined(__APPLE__)
		char path[1024];
		uint32_t size = sizeof(path);
		_NSGetExecutablePath(path, &size);
		full_path_to_maindir = path;
		full_path_to_maindir = full_path_to_maindir.substr(0, full_path_to_maindir.find_last_of(".") - 1);

#else
		char full_path_to_self[PATH_MAX];
		ssize_t len;

		//realpath("/proc/self/exe", tst);
		len = readlink("/proc/self/exe", full_path_to_self, sizeof(full_path_to_self));
		if (len == -1) {
			PRINT_ERROR("in readlink");
			return 2;
		}
		full_path_to_self[len] = '\x00'; // readlink does not null terminate!

		if (print_debug_info) {
			printf("[DBG] full_path_to_self='%s'\n", full_path_to_self);
		}

		full_path_to_maindir = full_path_to_self;
		full_path_to_maindir = full_path_to_maindir.substr(0, full_path_to_maindir.find_last_of('/'));
#endif

#if defined(__CYGWIN__)
		full_path_to_bins = full_path_to_maindir + "/" + "bin";
#else
		full_path_to_bins = convert_to_absolute_path(full_path_to_maindir) + "/" + "bin";
#endif

		full_path_to_maindir = convert_to_absolute_path(full_path_to_maindir);
	}

	full_path_to_keys = full_path_to_maindir + "/" + "keyfiles";


	// deprecated: full_path_to_wrk  = full_path_to_maindir + "/" + OUT_MAIN;
	// instead, we're going to run in the same place the RUU file is
	full_path_to_wrk = full_path_to_ruu_file;
	full_path_to_wrk = full_path_to_wrk.substr(0, full_path_to_wrk.find_last_of('/')) + "/" + OUT_MAIN;

	if (print_debug_info) {
		printf("[DBG] full_path_to_maindir='%s'\n", full_path_to_maindir.c_str());
		printf("[DBG] full_path_to_keys='%s'\n", full_path_to_keys.c_str());
		printf("[DBG] full_path_to_bins'%s'\n", full_path_to_bins.c_str());
		printf("[DBG] full_path_to_wrk'%s'\n", full_path_to_wrk.c_str());
		printf("[DBG] full_path_to_ruu_file='%s'\n", full_path_to_ruu_file.c_str());
		printf("[DBG] full_path_to_hb_file='%s'\n", full_path_to_hb_file.c_str());
		printf("[DBG] PATH='%s'\n", getenv("PATH"));
		printf("\n\n");
	}

	// all operations are going to be based in the wrk folder
	// it will be used a "base" for all functions
	if (access(full_path_to_wrk.c_str(), F_OK) == 0) {
		PRINT_INFO("");
		PRINT_ERROR("OUT folder already exists ('%s')\n       please delete it, we don't want to accidentally overwrite something you need.\n\n", full_path_to_wrk.c_str());
		return 2;
	}

	exit_code = mkdir(full_path_to_wrk.c_str(), 0777);
	exit_code |= change_dir(full_path_to_wrk);

	if (exit_code == 0) {
		exit_code |= mkdir(OUT_FIRMWARE, 0777);				// all files extracted from decrypted.zips
		exit_code |= mkdir(OUT_SYSTEM, 0777);				// assembled system.img

		exit_code |= mkdir(TMP_ROMZIP, 0777);				// either extract from RUU.EXE or move rom.zip here
		exit_code |= mkdir(TMP_DUMPED_ZIPS, 0777);			// individual zip files dumped from LargeZip or compressed Zip
		exit_code |= mkdir(TMP_DECRYPTED_ZIPS, 0777);		// all decrypted.zips
		exit_code |= mkdir(TMP_DECRYPTED_SYSIMGS, 0777);		// move system*.img* to here

		exit_code |= mkdir("tmp", 0777);						// tmp folder for bruutveal, android-info extraction, ruuveal test, new_keyfile.bin
	}

	if (exit_code) {
		PRINT_ERROR("Couldn't create [all] work folders, aborting!");
		return 2;
	}

	std::string path_android_info_file;
	android_info info;

	// begin main processing
	if (is_exe) {
		exit_code = UnRUU(full_path_to_ruu_file.c_str(), TMP_ROMZIP);
		if (exit_code == 0) {
			// android-info from RUU.EXE, will get overwritten later if found in decrypted zip
			path_android_info_file = find_file_from_pattern(TMP_ROMZIP, "*android-info*.txt*");
			info = Parse_Android_Info(path_android_info_file.c_str());

			PRINT_INFO("");
			PRINT_INFO("Information extracted from RUU.EXE:");
			if (!info.modelid.empty()) PRINT_INFO("    INFO: RUU modelid: %s", info.modelid.c_str());
			if (!info.mainver.empty()) PRINT_INFO("    INFO: RUU mainver: %s", info.mainver.c_str());
			PRINT_INFO("");
		}
	}
	else {
		PRINT_PROGRESS("Moving '%s' temporarily to working folder", path_ruuname.c_str());
		exit_code = move_file(full_path_to_ruu_file.c_str(), TMP_ROMZIP"/rom.zip");

		if (exit_code == 0) {
			// setup interrupt handler to restore file
			signal_full_path_to_tmpzip = full_path_to_wrk + "/" + TMP_ROMZIP"/rom.zip";
			signal_full_path_to_ruu_zip = full_path_to_ruu_file;

			// handle CTRL+C
			signal(SIGINT	, signal_Handler);	//	2	/* Interrupt (ANSI).  */

			// handle CTRL+Z
			signal(SIGTSTP	, signal_Handler);	//	20	/* Keyboard stop (POSIX).  */


			//signal(SIGHUP	, signal_Handler);	//	1	/* Hangup (POSIX).  */
			//signal(SIGQUIT	, signal_Handler);	//	3	/* Quit (POSIX).  */
			//signal(SIGABRT	, signal_Handler);	//	6	/* Abort (ANSI).  */


			//#define	SIGHUP		1	/* Hangup (POSIX).  */
			//#define	SIGINT		2	/* Interrupt (ANSI).  */
			//#define	SIGQUIT		3	/* Quit (POSIX).  */
			//#define	SIGILL		4	/* Illegal instruction (ANSI).  */
			//#define	SIGTRAP		5	/* Trace trap (POSIX).  */
			//#define	SIGABRT		6	/* Abort (ANSI).  */
			//#define	SIGIOT		6	/* IOT trap (4.2 BSD).  */
			//#define	SIGBUS		7	/* BUS error (4.2 BSD).  */
			//#define	SIGFPE		8	/* Floating-point exception (ANSI).  */
			//#define	SIGKILL		9	/* Kill, unblockable (POSIX).  */
			//#define	SIGUSR1		10	/* User-defined signal 1 (POSIX).  */
			//#define	SIGSEGV		11	/* Segmentation violation (ANSI).  */
			//#define	SIGUSR2		12	/* User-defined signal 2 (POSIX).  */
			//#define	SIGPIPE		13	/* Broken pipe (POSIX).  */
			//#define	SIGALRM		14	/* Alarm clock (POSIX).  */
			//#define	SIGTERM		15	/* Termination (ANSI).  */
			//#define	SIGSTKFLT	16	/* Stack fault.  */
			//#define	SIGCLD		SIGCHLD	/* Same as SIGCHLD (System V).  */
			//#define	SIGCHLD		17	/* Child status has changed (POSIX).  */
			//#define	SIGCONT		18	/* Continue (POSIX).  */
			//#define	SIGSTOP		19	/* Stop, unblockable (POSIX).  */
			//#define	SIGTSTP		20	/* Keyboard stop (POSIX).  */
			//#define	SIGTTIN		21	/* Background read from tty (POSIX).  */
			//#define	SIGTTOU		22	/* Background write to tty (POSIX).  */
			//#define	SIGURG		23	/* Urgent condition on socket (4.2 BSD).  */
			//#define	SIGXCPU		24	/* CPU limit exceeded (4.2 BSD).  */
			//#define	SIGXFSZ		25	/* File size limit exceeded (4.2 BSD).  */
			//#define	SIGVTALRM	26	/* Virtual alarm clock (4.2 BSD).  */
			//#define	SIGPROF		27	/* Profiling alarm clock (4.2 BSD).  */
			//#define	SIGWINCH	28	/* Window size change (4.3 BSD, Sun).  */
			//#define	SIGPOLL		SIGIO	/* Pollable event occurred (System V).  */
			//#define	SIGIO		29	/* I/O now possible (4.2 BSD).  */
			//#define	SIGPWR		30	/* Power failure restart (System V).  */
			//#define SIGSYS		31	/* Bad system call.  */
			//#define SIGUNUSED	31
		}
	}

	if (exit_code == 0) exit_code = ExtractZIPs(TMP_ROMZIP"/rom.zip", TMP_DUMPED_ZIPS);
	if (exit_code == 0 && is_exe && !keep_all_files && !create_sd_zip) delete_file(TMP_ROMZIP"/rom.zip");

	if (exit_code == 0) exit_code = KeyFinder(TMP_DUMPED_ZIPS, full_path_to_keys.c_str(), full_path_to_hb_file.c_str(), "tmp/use_keyfile.bin");

	if (exit_code == -1) 		exit_code = DecryptZIPs(TMP_DUMPED_ZIPS, TMP_DECRYPTED_ZIPS, NULL); //not encrypted
	else if (exit_code == 0)	exit_code = DecryptZIPs(TMP_DUMPED_ZIPS, TMP_DECRYPTED_ZIPS, "tmp/use_keyfile.bin");
	if ((exit_code == 0) && !keep_all_files) delete_dir_contents(TMP_DUMPED_ZIPS);

	if (exit_code == 0) exit_code = UnzipDecryptedZIPs(TMP_DECRYPTED_ZIPS, OUT_FIRMWARE);
	if ((exit_code == 0) && !keep_all_files) delete_dir_contents(TMP_DECRYPTED_ZIPS);

	if (exit_code == 0) {
		if (!create_firmware_only) {
			if (exit_code == 0) exit_code = MoveSystemIMGFiles(OUT_FIRMWARE, TMP_DECRYPTED_SYSIMGS);

			if (exit_code == 0) {
				int i;
				int num_of_sysimg_dirs;
				struct dirent **entry_list;

				num_of_sysimg_dirs = scandir(TMP_DECRYPTED_SYSIMGS, &entry_list, select_dirs, versionsort);
				if (is_scandir_error(entry_list, num_of_sysimg_dirs)) {
					PRINT_ERROR("No system img directories found!");
					exit_code = 2;
				}
				else {
					for (i = 0; i < num_of_sysimg_dirs; i++) {
						int exit_code_tmp = 0;
						char * sysimg_name = entry_list[i]->d_name;

						char in_dir[PATH_MAX];
						char out_file[PATH_MAX];

						sprintf(in_dir, "%s/%s", TMP_DECRYPTED_SYSIMGS, sysimg_name);
						sprintf(out_file, "%s/%s%s", OUT_SYSTEM, sysimg_name, ".img");

						if (exit_code_tmp == 0) exit_code_tmp = CreateSystemIMG(in_dir, out_file);
						if ((exit_code_tmp == 0) && !keep_all_files) { delete_dir_contents(in_dir); remove(in_dir); }

						if (exit_code_tmp == 0) exit_code_tmp = TestSystemIMG(out_file);

						exit_code |= exit_code_tmp;
					}
					free_dirent_entry_list(entry_list, num_of_sysimg_dirs);
				}
				remove(TMP_DECRYPTED_SYSIMGS);
			}

			PRINT_TITLE("Adding boot.img to the system folder");
			std::string path_bootimg_file = find_file_from_pattern(OUT_FIRMWARE, BOOTIMG);
			if (path_bootimg_file.empty()) {
				PRINT_ERROR("Couldn't find a %s to copy to system folder.", BOOTIMG);
			}
			else if (create_system_only) {
				PRINT_PROGRESS("Moving %s to %s", path_bootimg_file.c_str(), OUT_SYSTEM"/boot.img");
				move_file(path_bootimg_file.c_str(), OUT_SYSTEM"/boot.img");
			}
			else {
				PRINT_PROGRESS("Copying %s to %s", path_bootimg_file.c_str(), OUT_SYSTEM"/boot.img");
				copy_file(path_bootimg_file.c_str(), OUT_SYSTEM"/boot.img");
			}
		}

		path_android_info_file = find_file_from_pattern(OUT_FIRMWARE, "*android-info*.txt*");
		info = Parse_Android_Info(path_android_info_file.c_str());

		PRINT_TITLE("Checking keyfile state");
		if (ruuveal_device.empty()) {
			if (access("tmp/use_keyfile.bin", F_OK) == 0) {
				int res;

				res = Check_If_New_Keyfile("tmp/use_keyfile.bin", full_path_to_keys.c_str());

				if (res > 1)
					PRINT_ERROR("in Check_If_New_Keyfile (res=%i)", res);
				else if (res == 0) {
					PRINT_PROGRESS("Keyfile used already matches one in the keyfiles folder.");
					delete_file("tmp/use_keyfile.bin");
				}
				else {
					// move and rename keyfile
					std::string path_keyfile_file = info.modelid.substr(0, 4) + "_keyfile_" + info.mainver + ".bin";
					PRINT_PROGRESS("Moving keyfile to %s", path_keyfile_file.c_str());
					move_file("tmp/use_keyfile.bin", path_keyfile_file.c_str());

					PRINT_INFO("");
					PRINT_INFO("INFO: the keyfile '%s' generated appears to be new,", path_keyfile_file.c_str());
					PRINT_INFO("      please consider sharing/uploading it, so it can be included in future");
					PRINT_INFO("      releases of this tool, at:");
					PRINT_INFO("http://forum.xda-developers.com/chef-central/android/tool-universal-htc-ruu-rom-decryption-t3382928");
					PRINT_INFO("");
				}
			}
			else
				PRINT_PROGRESS("Unencrypted RUU, no keyfile was needed.");
			//printf("modelid='%s' ver='%s' keyfile='%s'", info.modelid.c_str(), info.mainver.c_str(), path_keyfile_file.c_str());
		}
		else {
			PRINT_PROGRESS("No keyfile was generated because ruuveal's built in '%s' device-key was used.", ruuveal_device.c_str());
		}
	}

	if (create_sd_zip && !info.modelid.empty()) {
		PRINT_TITLE("Copying rom.zip to OUT for SD-Card flashing");
		std::string path_sdzip_file = info.modelid.substr(0, 4) + "IMG.zip";
		if (is_exe) {
			PRINT_PROGRESS("file was a RUU.EXE so moving rom.zip to %s", path_sdzip_file.c_str());
			move_file(TMP_ROMZIP"/rom.zip", path_sdzip_file.c_str());
		}
		else {
			PRINT_PROGRESS("file was a ROM.ZIP so duplicating rom.zip to %s", path_sdzip_file.c_str());
			copy_file(TMP_ROMZIP"/rom.zip", path_sdzip_file.c_str());
		}
	}

	if (!is_exe) {
		PRINT_INFO("");
		PRINT_PROGRESS("Restoring '%s' to normal folder", path_ruuname.c_str());
		move_file(TMP_ROMZIP"/rom.zip", full_path_to_ruu_file.c_str());
	}
	else
		delete_file(TMP_ROMZIP"/rom.zip");


	// remove empty work folders (the others will remain)
	PRINT_INFO("");
	PRINT_INFO("");
	PRINT_PROGRESS("Removing unneeded work folders");
	remove(TMP_ROMZIP);
	remove(TMP_DUMPED_ZIPS);
	remove(TMP_DECRYPTED_ZIPS);
	remove(TMP_DECRYPTED_SYSIMGS);
	remove(OUT_FIRMWARE);
	remove(OUT_SYSTEM);
	remove("tmp");
	PRINT_INFO("");

	std::string full_path_to_final_out;
	full_path_to_final_out = full_path_to_wrk;

	if (!info.modelid.empty()) {
		PRINT_INFO("INFO: RUU modelid: %s", info.modelid.c_str());
		full_path_to_final_out += "_" + info.modelid.substr(0, 4);
	}
	if (!info.mainver.empty()) {
		PRINT_INFO("INFO: RUU mainver: %s", info.mainver.c_str());
		full_path_to_final_out += "_" + info.mainver;
	}
	PRINT_INFO("");

	if (access(full_path_to_final_out.c_str(), R_OK) == 0) {
		PRINT_INFO("Folder '%s' already exists! Keeping files in OUT folder.", full_path_to_final_out.c_str());
		PRINT_INFO("");
		full_path_to_final_out = full_path_to_wrk;
	}
	else
		rename(full_path_to_wrk.c_str(), full_path_to_final_out.c_str());

	//Finished: 
	if (exit_code == 0)
		PRINT_FINISHED("Successfully extracted zip files to\n             '%s'", full_path_to_final_out.c_str());
	else
		PRINT_FINISHED("Tool has finished but there was an error, please\n          check the console output and your OUT folder\n             '%s'", full_path_to_final_out.c_str());

	PRINT_INFO("");

	change_dir(path_cur.c_str());

	return exit_code;
}
