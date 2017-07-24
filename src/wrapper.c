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
#include <stdarg.h>

int __real_printf(const char *format, ...);

int __wrap_printf(const char *format, ...) {
	int res;

	va_list args;
	va_start(args, format);
	res = vfprintf(stderr, format, args);
	va_end(args);
	fflush(stderr);

	return res;
}

int __real_puts(const char *str);

int __wrap_puts(const char *str) {
	int res;
	res = fprintf(stderr, "%s\n", str);
	fflush(stderr);
	return res;
}

int __real_main(int argc, char * const *argv);

int __wrap_main(int argc, char * const *argv) {
	setvbuf(stdout, NULL, _IOLBF, 0);
	const char * identifier = "RUU_Decrypt_Tool_Wrapper"; // text to identify wrapped binaries
	return __real_main(argc, argv);
}
