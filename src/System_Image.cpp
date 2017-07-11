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
#include "System_Image.h"


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

	num_of_imgs = versionsort_scandir(".", &entry_list, select_files_systemimg);
	if (num_of_imgs < 0)
		return 2;
	else if (num_of_imgs == 0) {
		free_dirent_entry_list(entry_list, num_of_imgs);
		PRINT_ERROR("No img files found!");
		return 2;
	}

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

	num_of_imgs = versionsort_scandir(".", &entry_list, select_files_systemimg);
	if (num_of_imgs < 0) {
		exit_code = 2;
	}
	else if (num_of_imgs == 0) {
		free_dirent_entry_list(entry_list, num_of_imgs);
		PRINT_ERROR("No img files found!");
		exit_code = 2;
	}
	else {
		// PRINT_PROGRESS("Move %i system img files to system folder...", num_of_imgs);
		for (i = 0; i < num_of_imgs; i++) {
			char * file_name = entry_list[i]->d_name;
			base_system_name = file_name;

			found = base_system_name.rfind(".img");                                // remove everything from and including .img
			if (found != std::string::npos) base_system_name.erase(found);

			found = base_system_name.find_last_not_of("0123456789");               // remove any trailing numerical chars (multi part img file)
			if (found != std::string::npos) base_system_name.erase(found+1);

			found = base_system_name.find_last_not_of("_");                        // remove any other trailing chars we don't want
			if (found != std::string::npos) base_system_name.erase(found+1);
			//OR: if (base_system_name.back() == '_') base_system_name.pop_back(); // remove single trailing '_' (this needs c++11, so compile with -std=gnu++11)


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
