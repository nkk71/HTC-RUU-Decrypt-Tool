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
#include <fstream>
#include <iostream>


#include "Common.h"
#include "Utils.h"
#include "RUU_Functions.h"


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
