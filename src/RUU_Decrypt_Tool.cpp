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


#ifdef __CYGWIN__

#include <sys/cygwin.h>

// scandir stuff missing in cygwin
#include "strverscmp.c"
#include "versionsort.c"

#endif

//#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
#ifdef __CYGWIN__

#define AIK_BASE		"AIK-Windows"
#define AIK_UNPACK		AIK_BASE"/unpackimg.bat"
#define AIK_CLEANUP		AIK_BASE"/cleanup.bat"

#else

#define AIK_BASE		"AIK-Linux"
#define AIK_UNPACK		AIK_BASE"/unpackimg.sh"
#define AIK_CLEANUP		AIK_BASE"/cleanup.sh"

#endif //__CYGWIN__


#define VERSION_STRING "3.0.1"


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


// ==================================================================================
// ----------------------------------------------------------------------------------
// uncomment the below if you want to use system() call instead
// of forking and executing the other binaries
// (this works fine in linux, but breaks in cygwin, because i'm not including /bin/sh

// #define USE_SYSTEM_CALL
// ----------------------------------------------------------------------------------

// MAX_EXEC_ARGS is the maximum number of arguments passed through exec() calls,
// needs to accomodate the max number of args when using run_program
// including the max system*.img* files
#ifndef USE_SYSTEM_CALL
#define MAX_EXEC_ARGS 60
#endif
// ----------------------------------------------------------------------------------
// ==================================================================================


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
std::string ruuveal_device;

// =====================================================================
// file operations
// ---------------------------------------------------------------------
std::string convert_to_absolute_path(const char *path)
{
#ifdef __CYGWIN__
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
int change_dir(const char *path)
{
	if (chdir(path) != 0) {
		PRINT_ERROR("Couldn't cd to '%s'", path);
		return 0;
	}
	else
		return 1;
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
	std::ifstream srcfile(source, std::ios::binary);
	std::ofstream dstfile(destination, std::ios::binary | std::ios::out);

	dstfile << srcfile.seekg(skip).rdbuf();

	srcfile.close();
	dstfile.close();

	return 0;
}

int copy_file(const std::string *source, const std::string *destination, int skip = 0)
{
	return copy_file(source->c_str(), destination->c_str(), skip);
}
// ---------------------------------------------------------------------
int append_file(const char *source, const char *destination)
{
	std::ifstream srcfile(source, std::ios::binary);
	std::ofstream dstfile(destination, std::ios::binary | std::ios::out | std::ios::app);

	dstfile << srcfile.rdbuf();

	srcfile.close();
	dstfile.close();

	return 0;
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
// system calls
// ** system_args / system() calls out to shell (/bin/sh)
// ** which doesnt work well with cygwin
// ** so instead we fork a new process and use exec()
// ** unless USE_SYSTEM_CALL is defined
// ---------------------------------------------------------------------
#ifdef USE_SYSTEM_CALL

int system_args(const char *fmt, ...)
{
	int ret;
	char cmd[512];
	va_list ap;
	va_start(ap, fmt);

	ret = vsnprintf(cmd, sizeof(cmd), fmt, ap);
	if(ret < (int)sizeof(cmd))
	{
		ret = system(cmd);
	}
	else
	{
		char *buff = new char[ret+1];
		vsnprintf(buff, ret+1, fmt, ap);

		ret = system(buff);

		delete[] buff;
	}
	va_end(ap);

	return ret;
}

#else

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

		exec_args[i++] = (char *)bin_to_run;

		if (argv == NULL) {
			exec_args[i++] = NULL;
		}
		else {
			do {
				exec_args[i++] = argv[j++];
			} while (exec_args[i-1] != NULL);
		}


		//debug info
		/*
		{
			printf("1) about to execvp: '%s'", bin_to_run);
			int i = 0;
			while (exec_args[i] != NULL) {
				printf(" '%s'", exec_args[i++]);
			}
			printf("\n");
		}
		*/

		execvp(bin_to_run, exec_args);

		// we should not get here unless an error in exec() occurred
		PRINT_ERROR("something went wrong with exec() (errno=%i '%s')!", errno, strerror(errno));
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
#endif // USE_SYSTEM_CALL
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

	if ((file_name.find("system") != std::string::npos) && (file_name.find(".img") != std::string::npos))
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
		PRINT_PROGRESS("Testing keyfile '%s'...", basename(path_keyfile));
	else
		PRINT_PROGRESS("Testing ruuveal device '%s'...", ruuveal_device.c_str());

	int res;
	int exit_code = 0;

#ifdef USE_SYSTEM_CALL
				if (ruuveal_device.empty())
					res = system_args("ruuveal -K %s %s %s > /dev/null 2>&1", path_keyfile, path_enczip, "tmpzip.zip");
				else
					res = system_args("ruuveal --device %s %s %s > /dev/null 2>&1", ruuveal_device.c_str(), path_enczip, "tmpzip.zip");
#else
				// /dev/null 2>&1 redirection doesnt work this way in fork
				if (ruuveal_device.empty())
					res = run_program("ruuveal", "-K", path_keyfile, path_enczip, "tmpzip.zip", NULL);
				else
					res = run_program("ruuveal", "--device", ruuveal_device.c_str(), path_enczip, "tmpzip.zip", NULL);
#endif

	if (res == 0) {
		// PRINT_PROGRESS("keyfile passed ruuveal, running 2nd test...");

#ifdef USE_SYSTEM_CALL
		res = system_args("unzip -t %s", "tmpzip.zip");
#else
		res = run_program("unzip", "-t", "tmpzip.zip", NULL);
#endif

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

#ifdef USE_SYSTEM_CALL
		res = system_args("bruutveal %s %s %s", path_hboot_file, path_encrypted_zip_file, path_output_key_file);
#else
		res = run_program("bruutveal", path_hboot_file, path_encrypted_zip_file, path_output_key_file, NULL);
#endif

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

#ifdef USE_SYSTEM_CALL
		res = system_args("%s/"AIK_UNPACK" %s", full_path_to_bins.c_str(), full_path_hboot_file);
#else
		std::string full_path_to_AIK_script;

		full_path_to_AIK_script = full_path_to_bins;
		full_path_to_AIK_script += "/";
		full_path_to_AIK_script += AIK_UNPACK;

		res = run_program(full_path_to_AIK_script.c_str(), full_path_hboot_file, NULL);
#endif

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

#ifdef USE_SYSTEM_CALL
		system_args("%s/"AIK_CLEANUP, full_path_to_bins.c_str());
#else
		full_path_to_AIK_script = full_path_to_bins;
		full_path_to_AIK_script += "/";
		full_path_to_AIK_script += AIK_CLEANUP;

		run_program(full_path_to_AIK_script.c_str(), NULL);
#endif

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
#ifdef USE_SYSTEM_CALL
			system_args("unzip -n %s %s %s -d %s", zip_file, "hboot*", "hosd*", "tmp");
#else
			run_program("unzip", "-n", zip_file, "hboot*", "hosd*", "-d", "tmp", NULL);
#endif

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
			std::string test_file = "tmp";
			test_file += "/";
			test_file += entry_list[i]->d_name;

			if (KeyFinder_CheckInputFile(full_path_encrypted_zip_file, test_file.c_str(), full_path_output_key_file) == 0) {
				exit_code = 0; // yay
			}
		}
		free_dirent_entry_list(entry_list, num_of_files);
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
	if (!change_dir(path_inp_enczipfiles))
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

	if (is_user_supplied) {
		PRINT_INFO("");
		PRINT_PROGRESS("User supplied keyfile / hboot / hosd, going to test/generate...");
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

	if (!foundkey) {
		// try forcing extraction of hboot or hosd
		// this is a longshot and will likely not work, except for the RUUs that have the first zip signed but not encrypted
		res = KeyFinder_TryForceExtraction(full_path_encrypted_zip_file.c_str(), full_path_output_key_file.c_str());
		if (res == 0)
			foundkey = 1;
		else if (res > 1)
			PRINT_ERROR("in function TryForceExtraction (res=%i)", res);
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
	PRINT_TITLE("Attempting to create system.img");

	std::string path_base = get_absolute_cwd();
	std::string full_path_output_system_img_file = path_base + "/" + path_output_system_img_file;

	// we need to operate in the system.img folder folder
	if (!change_dir(path_inp_sysimgfiles))
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
		PRINT_PROGRESS("Single system.img found, moving it to output path");
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

#ifdef USE_SYSTEM_CALL
			res = system_args("simg2img %s %s", "system*", full_path_output_system_img_file.c_str());
#else
			// wildcards arent allowed in run_program
			char * args[MAX_EXEC_ARGS];
			for (i = 0; i < num_of_imgs; i++)
				args[i] = entry_list[i]->d_name;
			args[i] = (char *)full_path_output_system_img_file.c_str();
			args[i+1] = NULL;
			res = run_program("simg2img", args);
#endif

			if (res != 0) {
				PRINT_ERROR("could not create system.img (err=%i)", res);
				exit_code = 4;
			} else
				PRINT_PROGRESS("finished.");
		}

		else {
			PRINT_PROGRESS("Sparse Header not found, using simple concatenate");
			PRINT_PROGRESS("    Please be patient, this can take several minutes...");
			for (i = 0; i < num_of_imgs; i++) {
				file_name = entry_list[i]->d_name;
				PRINT_PROGRESS("    (%i/%i) %s -> system.img", i+1, num_of_imgs, file_name);
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
		PRINT_FINISHED("Successfully created system.img '%s'", path_output_system_img_file);

	change_dir(path_base);

	return exit_code;
}
/*==============================================================================================================================*/


/*==============================================================================================================================*/
int TestSystemIMG(const char *path_systemimg_file)
{
	PRINT_TITLE("Testing system.img...");

	int res;
	int exit_code = 0;

#ifdef USE_SYSTEM_CALL
	res = system_args("e2fsck -fn %s", path_systemimg_file);
#else
	res = run_program("e2fsck", "-fn", path_systemimg_file, NULL);
#endif

	if (res != 0) {
		PRINT_ERROR("system.img is corrupt (err=%i)", res);
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
		PRINT_FINISHED("system.img successfully passed filesystem check");

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
	if (!change_dir(path_inp_dumpedzips))
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

#ifdef USE_SYSTEM_CALL
				if (ruuveal_device.empty())
					res = system_args("ruuveal -K %s %s %s/dec_%s", full_path_key_file.c_str(), file_name, full_path_out_decryptedzips.c_str(), file_name);
				else
					res = system_args("ruuveal --device %s %s %s/dec_%s", ruuveal_device.c_str(), file_name, full_path_out_decryptedzips.c_str(), file_name);
#else
				if (ruuveal_device.empty())
					res = run_program("ruuveal", "-K", full_path_key_file.c_str(), file_name, (full_path_out_decryptedzips + "/" + "dec_" + file_name).c_str(), NULL);
				else
					res = run_program("ruuveal", "--device", ruuveal_device.c_str(), file_name, (full_path_out_decryptedzips + "/" + "dec_" + file_name).c_str(), NULL);
#endif

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

#ifdef USE_SYSTEM_CALL
						res = system_args("unzip -q -t %s", output_file.c_str());
#else
						res = run_program("unzip", "-q", "-t", output_file.c_str(), NULL);
#endif

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

#ifdef USE_SYSTEM_CALL
					res = system_args("unzip -q -t %s", file_name);
#else
					res = run_program("unzip", "-q", "-t", file_name, NULL);
#endif

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
	if (!change_dir(path_inp_zips))
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

#ifdef USE_SYSTEM_CALL
			if (create_system_only)
				res = system_args("unzip -n %s %s %s -d %s", file_name, SYSTEMIMG, BOOTIMG, full_path_to_outfiles.c_str());
			else if (create_firmware_only)
				res = system_args("unzip -n %s -x %s -d %s", file_name, SYSTEMIMG, full_path_to_outfiles.c_str());
			else
				res = system_args("unzip -n %s -d %s", file_name, full_path_to_outfiles.c_str());
#else
			if (create_system_only)
				res = run_program("unzip", "-n", file_name, SYSTEMIMG, BOOTIMG, "-d", full_path_to_outfiles.c_str(), NULL);
			else if (create_firmware_only)
				res = run_program("unzip", "-n", file_name, "-x", SYSTEMIMG, "-d", full_path_to_outfiles.c_str(), NULL);
			else
				res = run_program("unzip", "-n", file_name, "-d", full_path_to_outfiles.c_str(), NULL);
#endif
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

	// operate in the files folder
	if (!change_dir(path_inp_files))
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

			PRINT_PROGRESS("   (%i/%i) moving %s", i+1, num_of_imgs, file_name);
			if ((res = move_file(file_name, ".", full_path_to_outsystemimgs.c_str())) != 0) {
				PRINT_ERROR("could not move system img file (res=%i)", res);
				exit_code = 3;
			}
		}
		free_dirent_entry_list(entry_list, num_of_imgs);
	}

	change_dir(path_base);

	if (exit_code == 0)
		PRINT_FINISHED("Successfully moved system img files to '%s'", path_outsystemimgs);


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
	if (!change_dir(path_out))
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

#ifdef USE_SYSTEM_CALL
		res = system_args("ruuveal -D %s %s", full_path_to_ruu_file.c_str(), "dmp.zip");
#else
		res = run_program("ruuveal", "-D", full_path_to_ruu_file.c_str(), "dmp.zip", NULL);
#endif

		if (res != 0) {
			PRINT_ERROR("ruuveal returned error, aborting (err=%i)", res);
			exit_code = 4;
		}
	}

	else if (check_magic(full_path_to_ruu_file.c_str(), 0, ZIP_HEADER_MAGIC)) {
		// zip Header
		// possible TODO: check if that zip is actually an RUU, not just a regular zip
		PRINT_PROGRESS("Normal Zip format detected, using unzip");

#ifdef USE_SYSTEM_CALL
		res = system_args("unzip %s", full_path_to_ruu_file.c_str());
#else
		res = run_program("unzip", full_path_to_ruu_file.c_str(), NULL);
#endif

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
	PRINT_TITLE("Extracting rom.zip from %s", basename(path_ruu_exe_name));

	std::string path_base = get_absolute_cwd();

	// we need to operate in the out folder since unruu only outputs to current
	if (!change_dir(path_out))
		return 2;

	int exit_code = 0;
	int res;

#ifdef USE_SYSTEM_CALL
	res = system_args("unruu %s", path_ruu_exe_name);
#else
	res = run_program("unruu", path_ruu_exe_name, NULL);
#endif

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
	PRINT_INFO ("         by nkk71 and Captain_Throwback         ");
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

#ifdef USE_SYSTEM_CALL
	if (!system(NULL)) {
		PRINT_ERROR("command processor is not available!");
		return 2;
	}
#endif

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
		char full_path_to_self[PATH_MAX];

		//realpath("/proc/self/exe", tst);
		readlink("/proc/self/exe", full_path_to_self, sizeof(full_path_to_self));

		full_path_to_maindir = full_path_to_self;
		full_path_to_maindir = full_path_to_maindir.substr(0, full_path_to_maindir.find_last_of('/'));

		// setup the path here; cygwin doesn't like the real absolute paths
		std::string ENV_PATH =  full_path_to_maindir + "/" + "bin" + ":" + getenv("PATH");
		setenv("PATH", ENV_PATH.c_str(), 1);

		full_path_to_maindir = convert_to_absolute_path(full_path_to_maindir);
	}

	full_path_to_keys = full_path_to_maindir + "/" + "keyfiles";
	full_path_to_bins = full_path_to_maindir + "/" + "bin";


	// deprecated: full_path_to_wrk  = full_path_to_maindir + "/" + OUT_MAIN;
	// instead, we're going to run in the same place the RUU file is
	full_path_to_wrk = full_path_to_ruu_file;
	full_path_to_wrk = full_path_to_wrk.substr(0, full_path_to_wrk.find_last_of('/')) + "/" + OUT_MAIN;


	// all operations are going to be based in the wrk folder
	// it will be used a "base" for all functions
	if (access(full_path_to_wrk.c_str(), F_OK) == 0) {
		PRINT_INFO("");
		PRINT_ERROR("OUT folder already exists ('%s')\n       please delete it, we don't want to accidentally overwrite something you need.\n\n", full_path_to_wrk.c_str());
		return 2;
	}
	mkdir(full_path_to_wrk.c_str(), 0777);
	change_dir(full_path_to_wrk);

	mkdir(OUT_FIRMWARE, 0777);				// all files extracted from decrypted.zips
	mkdir(OUT_SYSTEM, 0777);				// assembled system.img

	mkdir(TMP_ROMZIP, 0777);				// either extract from RUU.EXE or move rom.zip here
	mkdir(TMP_DUMPED_ZIPS, 0777);			// individual zip files dumped from LargeZip or compressed Zip
	mkdir(TMP_DECRYPTED_ZIPS, 0777);		// all decrypted.zips
	mkdir(TMP_DECRYPTED_SYSIMGS, 0777);		// move system*.img* to here

	mkdir("tmp", 0777);						// tmp folder for bruutveal, android-info extraction, ruuveal test, new_keyfile.bin


	// begin main processing
	if (is_exe)
		exit_code = UnRUU(full_path_to_ruu_file.c_str(), TMP_ROMZIP);
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


	if (!create_firmware_only) {
		if (exit_code == 0) exit_code = MoveSystemIMGFiles(OUT_FIRMWARE, TMP_DECRYPTED_SYSIMGS);

		if (exit_code == 0) exit_code = CreateSystemIMG(TMP_DECRYPTED_SYSIMGS, OUT_SYSTEM"/system.img");
		if ((exit_code == 0) && !keep_all_files) delete_dir_contents(TMP_DECRYPTED_SYSIMGS);

		if (exit_code == 0) exit_code = TestSystemIMG(OUT_SYSTEM"/system.img");

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

	std::string path_android_info_file = find_file_from_pattern(OUT_FIRMWARE, "*android-info*.txt*");
	android_info info = Parse_Android_Info(path_android_info_file.c_str());

	PRINT_TITLE("Checking keyfile state");
	if (ruuveal_device.empty()) {
		// move and rename keyfile
		std::string path_keyfile_file = info.modelid.substr(0, 4) + "_keyfile_" + info.mainver + ".bin";
		if (access("tmp/use_keyfile.bin", F_OK) == 0) {
			PRINT_PROGRESS("Moving keyfile to %s", path_keyfile_file.c_str());
			move_file("tmp/use_keyfile.bin", path_keyfile_file.c_str());
		}
		else
			PRINT_PROGRESS("Unencrypted RUU, no keyfile was needed.");
		//printf("modelid='%s' ver='%s' keyfile='%s'", info.modelid.c_str(), info.mainver.c_str(), path_keyfile_file.c_str());
	}
	else {
		PRINT_PROGRESS("No keyfile was generated because ruuveal's built in '%s' device-key was used.", ruuveal_device.c_str());
	}

	if (create_sd_zip) {
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

	if (!info.modelid.empty()) PRINT_INFO("INFO: RUU modelid: %s", info.modelid.c_str());
	if (!info.mainver.empty()) PRINT_INFO("INFO: RUU mainver: %s", info.mainver.c_str());
	PRINT_INFO("");

	//Finished: 
	if (exit_code == 0)
		PRINT_FINISHED("Successfully extracted zip files to\n             '%s'", full_path_to_wrk.c_str());
	else
		PRINT_FINISHED("Tool has finished but there was an error, please\n          check the console output and your OUT folder\n             '%s'", full_path_to_wrk.c_str());

	PRINT_INFO("");

	change_dir(path_cur.c_str());

	return exit_code;
}
