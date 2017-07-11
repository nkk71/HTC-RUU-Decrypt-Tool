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
#include <dirent.h>

#include <string>

#include "Common.h"
#include "Utils.h"
#include "Zip_Handler.h"


/*==============================================================================================================================*/
std::string Find_First_Encrypted_ZIP(void)
{
	PRINT_PROGRESS("Find First Encrypted ZIP");

	int i;
	int num_of_zips;
	struct dirent **entry_list;
	std::string encrypted_zip;

	num_of_zips = versionsort_scandir(".", &entry_list, select_files_zip);
	if (num_of_zips < 0) {
		return "ERROR-1";
	}
	else if (num_of_zips == 0) {
		free_dirent_entry_list(entry_list, num_of_zips);
		PRINT_ERROR("No zip files found!");
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


	num_of_zips = versionsort_scandir(".", &entry_list, select_files_zip);
	if (num_of_zips < 0) {
		exit_code = 2;
	}
	else if (num_of_zips == 0) {
		free_dirent_entry_list(entry_list, num_of_zips);
		PRINT_ERROR("No zip files found!");
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
	num_of_zips = versionsort_scandir(".", &entry_list, select_files_zip);
	if (num_of_zips < 0) {
		exit_code = 2;
	}
	else if (num_of_zips == 0) {
		free_dirent_entry_list(entry_list, num_of_zips);
		PRINT_ERROR("No zip files found!");
		exit_code = 2;
	}
	else {
		for (i = 0; i < num_of_zips; i++) {
			char * file_name = entry_list[i]->d_name;

			PRINT_PROGRESS("\nUnzipping decrypted zip: (%i/%i) '%s'", i+1, num_of_zips, file_name);

			if (!create_system && !create_firmware)
				res = run_program("unzip", "-n", file_name, ANDROIDINFO, "-d", full_path_to_outfiles.c_str(), NULL);
			else if (create_system && !create_firmware)
				res = run_program("unzip", "-n", file_name, ANDROIDINFO, SYSTEMIMG, BOOTIMG, BOOTIMG_S, "-d", full_path_to_outfiles.c_str(), NULL);
			else if (create_firmware && !create_system)
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
