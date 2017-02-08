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

#ifndef _COMMON_H
#define _COMMON_H

#include <stdio.h>

#include <string>

#define UNIX

#ifdef UNIX
	#define RED			"\033[0;31m"
	#define GREEN		"\033[0;32m"
	#define BLUE		"\033[0;34m"
	#define BLDUND		"\033[1;4m"  //bold underline
	#define NOCOLOR		"\033[0m"    //No Color
#else
	// i'm using cygwin for windows compile, so these don't really matter
	#define RED			"\033[0;31m"
	#define GREEN		"\033[0;32m"
	#define BLUE		"\033[0;34m"
	#define BLDUND		"\033[1;4m"  //bold underline
	#define NOCOLOR		"\033[0m"    //No Color
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



// global variables
extern std::string full_path_to_maindir;
extern std::string full_path_to_keys;
extern std::string full_path_to_bins;
extern std::string full_path_to_wrk;

// program flags
extern int keep_all_files;
extern int do_immediate_cleanup;
extern int create_system_only;
extern int create_firmware_only;
extern int create_sd_zip;
extern int print_debug_info;
extern std::string ruuveal_device;

#endif // _COMMON_H
