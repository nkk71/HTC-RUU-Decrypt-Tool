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
#include <sstream> // for std::stringstream

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
#define PRINT_INFO(format, ...)      do { printf(format "\n", ##__VA_ARGS__); if (create_log_file) {char b[128]; snprintf(b, 128, format "\n", ##__VA_ARGS__); log_stream << b;} } while (0)
#define PRINT_DBG(format, ...)       do { fprintf(stderr, "DBG " format "\n", ##__VA_ARGS__); if (create_log_file) {char b[128]; snprintf(b, 128, "DBG " format "\n", ##__VA_ARGS__); log_stream << b;} } while (0)

#define PRINT_TITLE(format, ...)     do { printf("\n\n" BLUE BLDUND format NOCOLOR "\n", ##__VA_ARGS__); if (create_log_file) {char b[128]; snprintf(b, 128, "\n\n" format "\n", ##__VA_ARGS__); log_stream << b;} } while (0)
#define PRINT_PROGRESS(format, ...)  do { printf(BLUE format NOCOLOR "\n", ##__VA_ARGS__); if (create_log_file) {char b[128]; snprintf(b, 128, format "\n", ##__VA_ARGS__); log_stream << b;} } while (0)
#define PRINT_ERROR(format, ...)     do { printf(RED "ERROR: " format NOCOLOR "\n", ##__VA_ARGS__); if (create_log_file) {char b[128]; snprintf(b, 128, "ERROR: " format "\n", ##__VA_ARGS__); log_stream << b;} } while (0)
#define PRINT_FINISHED(format, ...)  do { printf(BLUE "Finished: " format NOCOLOR "\n", ##__VA_ARGS__); if (create_log_file) {char b[128]; snprintf(b, 128, "Finished: " format "\n", ##__VA_ARGS__); log_stream << b;} } while (0)
// =====================================================================



// global variables
extern std::string full_path_to_maindir;
extern std::string full_path_to_keys;
extern std::string full_path_to_bins;
extern std::string full_path_to_wrk;
extern std::stringstream log_stream;

// program flags
extern int keep_all_files;
extern int do_immediate_cleanup;
extern int create_system;
extern int create_firmware;
extern int create_sd_zip;
extern int print_debug_info;
extern std::string ruuveal_device;
extern int create_log_file;

#endif // _COMMON_H
