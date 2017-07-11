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
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include <string>

#include "Common.h"
#include "Utils.h"
#include "Zip_Handler.h"
#include "Key_Finder.h"


// used by --device DEVICE
#include "ruuveal/htc/devices.h"


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
		num_of_keys = versionsort_scandir(".", &entry_list, select_files_keyfiles);
		if (num_of_keys < 0) {
			exit_code = 5;
		}
		else {
			for (i = 0; i < num_of_keys; i++) {
				pFile = fopen(entry_list[i]->d_name, "rb" );
				if (pFile == NULL) {
					exit_code = 6; // couldnt open file
					PRINT_ERROR("Couldn't open '%s' (please check your keyfile folder for corrupt keyfiles)", entry_list[i]->d_name);
				}
				else {
					if (fread(buffer_chk_key, 1, KEYFILE_SIZE, pFile) != KEYFILE_SIZE) {
						exit_code = 7; // couldnt read buffer
						PRINT_ERROR("Couldn't read '%s' (please check your keyfile folder for corrupt keyfiles)", entry_list[i]->d_name);
					}
					else if (memcmp(buffer_new_key, buffer_chk_key, KEYFILE_SIZE) == 0)
						exit_code = 0; // key already exists

				fclose(pFile);
				}

				if (exit_code == 0)
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
		// Add keyfile error checking here!!
		exit_code = 1;
	}

	if (exit_code == 0) {
		PRINT_PROGRESS("INFO: keyfile passed all tests");
	}

	delete_file("tmpzip.zip");

	return exit_code;
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
	} else {
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

		change_dir(full_path_to_wrk);
		res = run_program("magiskboot", "--unpack", full_path_hboot_file, NULL);

		if (res == 0) {
			res = run_program("magiskboot", "--cpio-extract", "ramdisk.cpio", "sbin/downloadzip", "downloadzip", NULL);
			if (res == 0) {
				std::string downloadzip = full_path_to_wrk + "/downloadzip";
				if (access(downloadzip.c_str(), R_OK) == 0) {
					if (Run_BRUUTVEAL(downloadzip.c_str(), full_path_encrypted_zip_file, full_path_output_key_file) == 0) {
						exit_code = 0;
					}
					delete_file(full_path_to_wrk + "/downloadzip");
				}
				else {
					PRINT_ERROR("hosd unpacked, but couldn't access downloadzip file");
					exit_code = 3;
				}
			}
			else {
					PRINT_ERROR("Unable to extract downloadzip (res=%i)", res);
					exit_code = 3;
			}
			res = run_program("magiskboot", "--cleanup", NULL);
		}
		else {
			PRINT_ERROR("Unable to unpack hosd (res=%i)", res);
			exit_code = 4;
		}
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

	num_of_keys = versionsort_scandir(full_path_keys, &entry_list, select_files_keyfiles);
	if (num_of_keys < 0) {
		exit_code = 2;
	}
	else {
		if (num_of_keys == 0)
			PRINT_INFO("Your keyfile folder is empty!");
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
	num_of_zips = versionsort_scandir(".", &entry_list, select_files_zip);
	if (num_of_zips < 0) {
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
	num_of_files = versionsort_scandir("tmp", &entry_list, select_files_any);
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
