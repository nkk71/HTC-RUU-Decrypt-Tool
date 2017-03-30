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

#include <string>

#include "Common.h"
#include "Utils.h"


int Download_Keyfiles(const char *path_keyfiles)
{
	PRINT_TITLE("Downloading keyfiles...");

	std::string path_base = get_absolute_cwd();

	if (change_dir(path_keyfiles))
		return 2;

	int exit_code = run_program("keyfile_updater", "--download-new", NULL);

	change_dir(path_base);

	return exit_code;
}


int Upload_Keyfile(const char *path_keyfile)
{
	PRINT_TITLE("Uploading new keyfile...");

	std::string path_base = get_absolute_cwd();

	int exit_code = run_program("keyfile_updater", "--upload-new", path_keyfile, NULL);

	if (exit_code != 0)
		PRINT_ERROR("Uploading new keyfile failed.");

	change_dir(path_base);

	return exit_code;
}

int Sync_Keyfiles(const char *path_keyfiles)
{
	PRINT_TITLE("Synchronizing keyfiles...");

	std::string path_base = get_absolute_cwd();

	if (change_dir(path_keyfiles))
		return 2;

	int exit_code = 0;

	// First download from the server
	PRINT_PROGRESS("1) Downloading keyfiles...");
	exit_code = run_program("keyfile_updater", "--download-new", NULL);

	PRINT_INFO("");

	// Now upload anything not already on the server
	PRINT_PROGRESS("2) Uploading keyfiles...");
	exit_code |= run_program("keyfile_updater", "--upload-new", NULL);

	change_dir(path_base);

	return exit_code;
}
