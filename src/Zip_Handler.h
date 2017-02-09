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

#ifndef _ZIP_HANDLER_H
#define _ZIP_HANDLER_H

#include <string>

// Header MAGICs
#define HTC_LARGEZIP_HEADER_MAGIC   "LaR@eZip"
#define ZIP_HEADER_MAGIC            "PK\x03\x04"
#define HTC_ZIP_HEADER_MAGIC        "Htc@egi$"

// zip extraction inclusion / exclusion
#define SYSTEMIMG   "system*.img*"
#define ANDROIDINFO "*android-info*.txt*"
#define BOOTIMG     "boot.img"
#define BOOTIMG_S   "boot_*.img"


std::string Find_First_Encrypted_ZIP(void);
int DecryptZIPs(const char *path_inp_dumpedzips, const char *path_out_decryptedzips, const char *path_key_file);
int UnzipDecryptedZIPs(const char *path_inp_zips, const char *path_outfiles);
int ExtractZIPs(const char *path_to_ruu_file, const char *path_out);

#endif // _ZIP_HANDLER_H
