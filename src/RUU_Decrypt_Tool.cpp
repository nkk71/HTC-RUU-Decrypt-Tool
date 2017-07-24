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
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>

#include <string>
#include <iostream> // for std::cout
#include <fstream>  // for std::ofstream
#include <sstream>  // for std::stringstream

#if defined( __APPLE__)
	// mac specific header
	#include <mach-o/dyld.h>
#endif

#include "Common.h"
#include "Utils.h"
#include "System_Image.h"
#include "Key_Finder.h"
#include "Zip_Handler.h"
#include "RUU_Functions.h"
#include "Updater.h"
#include "Time_Functions.h"

#include "RUU_Decrypt_Tool.h"

// used by --device DEVICE
#include "ruuveal/htc/devices.h"
#include "ruuveal/htc/devices.c"


// global variables
std::string full_path_to_maindir;
std::string full_path_to_keys;
std::string full_path_to_bins;
std::string full_path_to_wrk;
std::stringstream log_stream;

// program flags
int keep_all_files = 0;
int do_immediate_cleanup = 1;
int create_system = 0;
int create_firmware = 0;
int create_sd_zip = 0;
int print_debug_info = 0;
int wait_for_enter = 0;
int allow_download = 0;
int allow_upload = 0;
std::string ruuveal_device;
int create_log_file = 0;

// needed for signal handling, so we dont loose tmp/romzip/rom.zip if it was a rom.zip on an abort
std::string signal_full_path_to_tmpzip;
std::string signal_full_path_to_ruu_zip;


void write_log_file(std::string filename = "")
{
	if (!create_log_file || filename.empty())
		return;

	std::cout << "Writing logfile to: " << get_absolute_cwd() << "/" << filename << std::endl;
	log_stream << "Writing logfile to: " << get_absolute_cwd() << "/" << filename << std::endl;

	std::ofstream log_file(filename.c_str(), std::ofstream::out);
	if (log_file.is_open()) {
		log_file << log_stream.str() << std::endl;
		log_file.close();
	}
	else {
		std::cout << "Error writing logfile (" << strerror(errno) << ")!" << std::endl;
	}
}


// interrupt handler in case we need to move the original rom.zip back to origin
void signal_Handler(int sig_num)
{
	printf("\nE-SIGNAL received signal=%i\n", sig_num);
	if (!signal_full_path_to_tmpzip.empty()) {
		printf("rom.zip was moved, try moving it back to origin\n");
		rename(signal_full_path_to_tmpzip.c_str(), signal_full_path_to_ruu_zip.c_str());
	}

	fflush(stdout); fflush(stderr);
	write_log_file();

	// OUT cleanup
	change_dir("/");
	if (!full_path_to_wrk.empty()) {
		remove((full_path_to_wrk + TMP_ROMZIP).c_str());
		remove((full_path_to_wrk + TMP_DUMPED_ZIPS).c_str());
		remove((full_path_to_wrk + TMP_DECRYPTED_ZIPS).c_str());
		remove((full_path_to_wrk + TMP_DECRYPTED_SYSIMGS).c_str());
		remove((full_path_to_wrk + OUT_FIRMWARE).c_str());
		remove((full_path_to_wrk + OUT_SYSTEM).c_str());
		remove((full_path_to_wrk + "tmp").c_str());
		remove(full_path_to_wrk.c_str());
	}

	exit(sig_num);
}


// Prompts the user for a Y or N character. (returns 1 for Y, 0 for N)
int Prompt_User_YN(const char *prompt_text, int default_char)
{
	int answer;
	int c;
	int num_of_chars;

	default_char = tolower(default_char);

	do {
		printf("%s", prompt_text);
		printf("%c", toupper(default_char)); printf("\033[1D");
		fflush(stdout);

		answer = 0;
		num_of_chars = 0;

		// loop till end of line to avoid having extra chars in the buffer
		while ((c = getchar()) != EOF && c != '\n') {
			num_of_chars++;
			c = tolower(c);
			if (c == 'y' || c == 'n')
				answer = c;
			//else
			//	printf("\t Wrong input, please answer with Y or N !\n");
		}

		if (num_of_chars == 0 && c == '\n') {
			answer = default_char;
		}
		else if (num_of_chars > 1) {
			printf("\n\t Too many characters, please answer with Y or N !\n\n");
			answer = 0;
		}
		else if (c != '\n')
			printf("\n");

	} while (answer != 'y' && answer != 'n');

	fflush(stdin);
	fflush(stdout);
	fflush(stderr);

	if (create_log_file)
		log_stream << prompt_text << (char)answer << std::endl;

	return answer == 'y';
}


void press_enter_to_exit(void)
{
#if defined(__CYGWIN__)
	// For the Windows drag and droppers
	// Not the nicest nor really reliable way to do it,
	// but easy enough, considering ppid doesn't work.
	// Maybe better to add a command line flag instead.
	wait_for_enter = getenv("PROMPT") == NULL;
#endif

	if (wait_for_enter) {
		int c;
		PRINT_INFO("Press ENTER to exit");
		while ((c = getchar()) != EOF && c != '\n');
	}
}

void Print_Usage(std::string ProgramName)
{
	PRINT_INFO("");
	PRINT_INFO("Usage: %s [options] <RUUName: RUU.exe or ROM.zip> [keyfile/hboot/hosd]", ProgramName.c_str());
	PRINT_INFO("");
	PRINT_INFO("   If none of the required arguments are supplied a simple Yes/No interface will be presented.");
	PRINT_INFO("");
	PRINT_INFO("   Required arguments (and/or):");
	PRINT_INFO("      -s, --system     extract the system.img and boot.img (for ROM)");
	PRINT_INFO("      -f, --firmware   extract the firmware files");
	PRINT_INFO("      -z, --sdruuzip   copy and rename rom.zip for SD-Card flashing");
	PRINT_INFO("                       Note: this will create a duplicate if the input is already a rom.zip");
	PRINT_INFO("");
	PRINT_INFO("   Keyfile Updater arguments:");
	PRINT_INFO("      -o, --offline     disable down/upload of keyfiles");
	PRINT_INFO("      --no-upload       do not upload if a new keyfile is generated");
	PRINT_INFO("      --sync-keyfiles   sync entire keyfile folder (download & upload)");
	PRINT_INFO("                        when used without a RUU the tool will only synchronize the");
	PRINT_INFO("                        keyfiles, otherwise it will download new keyfiles before decrypting");
	PRINT_INFO("                        and upload only if a new keyfile is generated");
	PRINT_INFO("");
	PRINT_INFO("   Logging:");
	PRINT_INFO("      -L, --log [filename]   log all output to a txt file");
	PRINT_INFO("                             'filename' is optional, the default would be:");
	PRINT_INFO("                             RUU_Decrypt_LOG-{MID}_{MAINVER}.txt in the OUT folder");
	PRINT_INFO("");
	PRINT_INFO("   Debugging Options (not usually needed):");
	PRINT_INFO("      -k, --keepall          keep all intermediary files");
	PRINT_INFO("      -c, --slowcleanup      do a 'slow cleanup', ie dont delete files once partially processed");
	PRINT_INFO("      -P, --debuginfo        print debug info (paths and exec)");
	PRINT_INFO("");
	PRINT_INFO("   Direct ruuveal support (needed for older devices):");
	PRINT_INFO("      -d, --device DEVICE  specify device (this is only needed for old unruu supported devices)");
	PRINT_INFO("                           please run ruuveal to see the list of DEVICEs supported");
	PRINT_INFO("");
	PRINT_INFO("");
}

int Parse_CommandLine(int argc, char **argv, std::string &path_ruuname, std::string &path_hb)
{
	struct option longopts[] = {
		// Main Options
		{ "system",   no_argument, NULL, 's' },
		{ "firmware", no_argument, NULL, 'f' },
		{ "sdruuzip", no_argument, NULL, 'z' },

		// keyfile updater
		{ "offline",       no_argument, NULL, 'o' },
		{ "no-upload",     no_argument, NULL, 'N' },  // 'N' and 'S' are used for simplicity, that may be changed
		{ "sync-keyfiles", no_argument, NULL, 'S' },  // in the future, so only the long options should be used !

		// Logging
		{ "log", optional_argument, NULL, 'L' },

		// Debugging Options
		{ "keepall",     no_argument, NULL, 'k' },
		{ "slowcleanup", no_argument, NULL, 'c' },
		{ "debuginfo",   no_argument, NULL, 'P' },

		// Direct ruuveal support
		{ "device", required_argument, NULL, 'd' },

		{ 0, 0, 0, 0}
	};

	int c;
	int opt_count = 0;

	while ((c = getopt_long(argc, argv, "-sfzkcPd:oL", longopts, NULL)) != -1) {
		switch (c) {
			case 's':
				opt_count++;
				create_system = 1;
				break;
			case 'f':
				opt_count++;
				create_firmware = 1;
				break;
			case 'z':
				opt_count++;
				create_sd_zip = 1;
				break;

			case 'o':
				opt_count++;
				allow_download = 0;
				allow_upload = 0;
				break;
			case 'N':
				opt_count++;
				allow_download = 1;
				allow_upload = 0;
				break;
			case 'S':
				opt_count++;
				allow_download = 2;
				allow_upload = 2;
				break;

			case 'L':
				opt_count++;
				create_log_file = 2;
				//if (optarg)
				//	log_file_name = optarg;
				break;

			case 'k':
				opt_count++;
				keep_all_files = 1;
				do_immediate_cleanup = 0;
				break;
			case 'c':
				opt_count++;
				do_immediate_cleanup = 0;
				break;
			case 'P':
				opt_count++;
				print_debug_info = 1;
				break;

			case 'd':
				opt_count++;
				if (!optarg) {
					PRINT_ERROR("No DEVICE parameter specified for --device DEVICE option.");
					press_enter_to_exit();
					write_log_file();
					return 1;
				}
				else {
					ruuveal_device = optarg;

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
						PRINT_INFO("supported devices:-\n");
						for(ptr = htc_get_devices(); *ptr->name; ptr++) {
							PRINT_INFO("* %s (%s)", ptr->desc, ptr->name);
						}
						PRINT_INFO("");
						press_enter_to_exit();
						write_log_file();
						exit(1);
					}
				}
				break;

			case 1:
				if (optarg) {
					if (path_ruuname.empty())
						path_ruuname = optarg;
					else if (!path_ruuname.empty())
						path_hb = optarg;
					else {
						PRINT_ERROR("Too many arguments!");
						return -1;
					}
				}
				break;

			case ':':   /* missing option argument */
				PRINT_ERROR("Option -%c requires an argument!", c);
				return -1;
				break;

			case '?':
			default:
				PRINT_ERROR("Invalid option specified!");
				return -1;
				break;
		}
	}

	return opt_count;
}

int main(int argc, char **argv)
{
	Timer_ToolStart();
	create_log_file = 1;

	PRINT_TITLE("+++ Welcome to the HTC RUU Decryption Tool %s +++", VERSION_STRING);
	PRINT_INFO("");

	int exit_code = 0;
	int is_exe;

	std::string path_cur = get_absolute_cwd();
	std::string cmd_name = argv[0];

	std::string path_ruuname;
	std::string path_hb;


	int options = Parse_CommandLine(argc, argv, path_ruuname, path_hb);

	if (options > 0 && create_log_file != 2)
		create_log_file = 0;

	if (options < 0 || (path_ruuname.empty() && allow_download != 2)) {
		Print_Usage(cmd_name);
		press_enter_to_exit();
		write_log_file();
		return 1;
	}

	// setup global paths
	{
#if defined(__APPLE__)
		char path[1024];
		uint32_t size = sizeof(path);
		_NSGetExecutablePath(path, &size);
		full_path_to_maindir = path;
		full_path_to_maindir = full_path_to_maindir.substr(0, full_path_to_maindir.find_last_of(".") - 1);
#else
		char full_path_to_self[PATH_MAX];
		ssize_t len;

		//realpath("/proc/self/exe", tst);
		len = readlink("/proc/self/exe", full_path_to_self, sizeof(full_path_to_self));
		if (len == -1) {
			PRINT_ERROR("in readlink");
			press_enter_to_exit();
			write_log_file();
			return 2;
		}
		full_path_to_self[len] = '\x00'; // readlink does not null terminate!

		if (print_debug_info) {
			PRINT_DBG("full_path_to_self='%s'", full_path_to_self);
		}

		full_path_to_maindir = full_path_to_self;
		full_path_to_maindir = full_path_to_maindir.substr(0, full_path_to_maindir.find_last_of('/'));
#endif

#if defined(__CYGWIN__)
		full_path_to_bins = full_path_to_maindir + "/" + "bin";
#else
		full_path_to_bins = convert_to_absolute_path(full_path_to_maindir) + "/" + "bin";
#endif

		full_path_to_maindir = convert_to_absolute_path(full_path_to_maindir);
	}

#if defined(__ANDROID__)
	full_path_to_keys = "/sdcard/RUU_Decrypt_Tool/keyfiles";
	mkdir("/sdcard/RUU_Decrypt_Tool", 0777);
#else
	full_path_to_keys = full_path_to_maindir + "/" + "keyfiles";
#endif
	mkdir(full_path_to_keys.c_str(), 0777);

	if (path_ruuname.empty() && allow_download && allow_upload) {
		// Sync only option
		Sync_Keyfiles(full_path_to_keys.c_str());
		write_log_file();
		return 0;
	}

	std::string full_path_to_ruu_file;
	std::string full_path_to_hb_file;
	{
		char tmp_filename_buffer[PATH_MAX];

		if (realpath(path_ruuname.c_str(), tmp_filename_buffer) == NULL) {
			PRINT_ERROR("Couldn't resolve full path to file '%s'!", path_ruuname.c_str());
			press_enter_to_exit();
			write_log_file();
			return 2;
		}
		else
			full_path_to_ruu_file = convert_to_absolute_path(tmp_filename_buffer);


		if (!path_hb.empty()) {
			if (realpath(path_hb.c_str(), tmp_filename_buffer) == NULL) {
				PRINT_ERROR("Couldn't resolve full path to file '%s'!", path_hb.c_str());
				press_enter_to_exit();
				write_log_file();
				return 2;
			}
			else
				full_path_to_hb_file = convert_to_absolute_path(tmp_filename_buffer);
		}
	}

	is_exe = 0;
	if (access(full_path_to_ruu_file.c_str(), R_OK)) {
		PRINT_ERROR("Couldn't read file '%s'!", full_path_to_ruu_file.c_str());
		press_enter_to_exit();
		write_log_file();
		return 2;
	}
	else if (check_magic(full_path_to_ruu_file.c_str(), 0, IMAGE_DOS_SIGNATURE)) {
		PRINT_PROGRESS("RUU identified as Executable file");
		is_exe = 1;
	}
	else if (check_magic(full_path_to_ruu_file.c_str(), 0, HTC_LARGEZIP_HEADER_MAGIC))   // LargeZip
		PRINT_PROGRESS("RUU identified as HTC LargeZip file");
	else if (check_magic(full_path_to_ruu_file.c_str(),   0, ZIP_HEADER_MAGIC))          // Normal zip
		PRINT_PROGRESS("RUU identified as Normal Zip file");
	else if (check_magic(full_path_to_ruu_file.c_str(), 256, ZIP_HEADER_MAGIC))          // Normal zip + signed
		PRINT_PROGRESS("RUU identified as Normal Signed Zip file");
	else if (check_magic(full_path_to_ruu_file.c_str(),   0, HTC_ZIP_HEADER_MAGIC))      // HTC Encrypted zip
		PRINT_PROGRESS("RUU identified as HTC Encrypted Zip file");
	else if (check_magic(full_path_to_ruu_file.c_str(), 256, HTC_ZIP_HEADER_MAGIC))      // HTC Encrypted zip + signed
		PRINT_PROGRESS("RUU identified as HTC Singed Encrypted Zip file");
	else {
		PRINT_ERROR("Couldn't identify '%s' file format!", path_ruuname.c_str());
		press_enter_to_exit();
		write_log_file();
		return 2;
	}

	// deprecated: full_path_to_wrk  = full_path_to_maindir + "/" + OUT_MAIN;
	// instead, we're going to run in the same place the RUU file is
	full_path_to_wrk = full_path_to_ruu_file;
	full_path_to_wrk = full_path_to_wrk.substr(0, full_path_to_wrk.find_last_of('/')) + "/" + OUT_MAIN;

	// all operations are going to be based in the wrk folder
	// it will be used a "base" for all functions
	if (access(full_path_to_wrk.c_str(), F_OK) == 0) {
		PRINT_INFO("");
		PRINT_ERROR("OUT folder already exists ('%s')\n       please delete it, we don't want to accidentally overwrite something you need.\n\n", full_path_to_wrk.c_str());
		press_enter_to_exit();
		write_log_file();
		return 2;
	}

	if (options == 0) {
		// No command line options specified, present simple Y/N interface
		PRINT_TITLE("Please enter your choices");
		create_log_file = Prompt_User_YN("* Create a logfile [Y/n]: ", 'Y');

		create_system = Prompt_User_YN("* Extract system.img and boot.img [Y/n]: ", 'Y');
		create_firmware = Prompt_User_YN("* Extract the firmware files [Y/n]: ", 'Y');
		create_sd_zip = Prompt_User_YN("* Create an sd-card flashable zip [y/N]: ", 'N');

		allow_download = Prompt_User_YN("* Do you wish to check for new keyfiles [Y/n]: ", 'Y');
		allow_upload   = Prompt_User_YN("* If a new keyfile is generated, do you wish to upload it [Y/n]: ", 'Y');

		if (Prompt_User_YN("* Enable debugging options [y/N]: ", 'N')) {
			print_debug_info = Prompt_User_YN("     * Print Debug Info [y/N]: ", 'N');
			do_immediate_cleanup = ! Prompt_User_YN("     * Do a 'slow cleanup' [y/N]: ", 'N');
			keep_all_files = Prompt_User_YN("     * Keep all intermediary files [y/N]: ", 'N');
		}
		printf("\n");
		fflush(stdin);
		fflush(stdout);
		fflush(stderr);
		printf("\n");
		printf("\n");
		Timer_ToolStart(); // Update start time due to *GUI* :P
	}

	if (print_debug_info) {
		PRINT_DBG("full_path_to_maindir='%s'", full_path_to_maindir.c_str());
		PRINT_DBG("full_path_to_keys='%s'", full_path_to_keys.c_str());
		PRINT_DBG("full_path_to_bins'%s'", full_path_to_bins.c_str());
		PRINT_DBG("full_path_to_wrk'%s'", full_path_to_wrk.c_str());
		PRINT_DBG("full_path_to_ruu_file='%s'", full_path_to_ruu_file.c_str());
		PRINT_DBG("full_path_to_hb_file='%s'", full_path_to_hb_file.c_str());
		PRINT_DBG("PATH='%s'", getenv("PATH"));
		PRINT_INFO("");
		PRINT_INFO("");
	}

	exit_code = mkdir(full_path_to_wrk.c_str(), 0777);
	exit_code |= change_dir(full_path_to_wrk);

	if (exit_code == 0) {
		exit_code |= mkdir(OUT_FIRMWARE, 0777);           // all files extracted from decrypted.zips
		exit_code |= mkdir(OUT_SYSTEM, 0777);             // assembled system.img

		exit_code |= mkdir(TMP_ROMZIP, 0777);             // either extract from RUU.EXE or move rom.zip here
		exit_code |= mkdir(TMP_DUMPED_ZIPS, 0777);        // individual zip files dumped from LargeZip or compressed Zip
		exit_code |= mkdir(TMP_DECRYPTED_ZIPS, 0777);     // all decrypted.zips
		exit_code |= mkdir(TMP_DECRYPTED_SYSIMGS, 0777);  // move system*.img* to here

		exit_code |= mkdir("tmp", 0777);                  // tmp folder for bruutveal, android-info extraction, ruuveal test, new_keyfile.bin
	}

	if (exit_code) {
		PRINT_ERROR("Couldn't create [all] work folders, aborting!");
		press_enter_to_exit();
		write_log_file();
		return 2;
	}

	// setup interrupt handler
	signal_full_path_to_tmpzip.clear();  // this will be set later if the zip actually get's moved
	signal_full_path_to_ruu_zip = full_path_to_ruu_file;
	signal(SIGINT , signal_Handler);     // handle CTRL+C  //   2  /* Interrupt (ANSI).  */
	signal(SIGTSTP, signal_Handler);     // handle CTRL+Z  //  20  /* Keyboard stop (POSIX).  */


	if (allow_download)
		TIME_OPERATION( "Download_Keyfiles", Download_Keyfiles(full_path_to_keys.c_str()); );

	std::string path_android_info_file;
	android_info info;

	// begin main processing
	if (is_exe) {
		TIME_OPERATION( "unruu", exit_code = UnRUU(full_path_to_ruu_file.c_str(), TMP_ROMZIP); );
		if (exit_code == 0) {
			// android-info from RUU.EXE, will get overwritten later if found in decrypted zip
			path_android_info_file = find_file_from_pattern(TMP_ROMZIP, "*android-info*.txt*");
			info = Parse_Android_Info(path_android_info_file.c_str());

			PRINT_INFO("");
			PRINT_INFO("Information extracted from RUU.EXE:");
			// if (info.modelid.empty() && info.mainver.empty())
			//    huh -_-
			if (!info.modelid.empty()) PRINT_INFO("    INFO: RUU modelid: %s", info.modelid.c_str());
			if (!info.mainver.empty()) PRINT_INFO("    INFO: RUU mainver: %s", info.mainver.c_str());
			PRINT_INFO("");
		}
	}
	else {
		PRINT_PROGRESS("Moving '%s' temporarily to working folder", path_ruuname.c_str());
		exit_code = move_file(full_path_to_ruu_file.c_str(), TMP_ROMZIP"/rom.zip");

		if (exit_code == 0) {
			// setup interrupt handler to restore file
			signal_full_path_to_tmpzip = full_path_to_wrk + "/" + TMP_ROMZIP"/rom.zip";
			signal_full_path_to_ruu_zip = full_path_to_ruu_file;
		}
	}

	//TODO: fix code for (create_sd_zip && !create_system && !create_firmware)

	if (exit_code == 0) TIME_OPERATION( "ExtractZIPs", exit_code = ExtractZIPs(TMP_ROMZIP"/rom.zip", TMP_DUMPED_ZIPS); );
	if (exit_code == 0 && is_exe && !keep_all_files && !create_sd_zip) delete_file(TMP_ROMZIP"/rom.zip");

	if (exit_code == 0) TIME_OPERATION( "KeyFinder", exit_code = KeyFinder(TMP_DUMPED_ZIPS, full_path_to_keys.c_str(), full_path_to_hb_file.c_str(), "tmp/use_keyfile.bin"); );

	if (exit_code == -1) TIME_OPERATION( "DecryptZIPs ", exit_code = DecryptZIPs(TMP_DUMPED_ZIPS, TMP_DECRYPTED_ZIPS, NULL); ); //not encrypted
	else if (exit_code == 0) TIME_OPERATION( "DecryptZIPs", exit_code = DecryptZIPs(TMP_DUMPED_ZIPS, TMP_DECRYPTED_ZIPS, "tmp/use_keyfile.bin"); );
	if ((exit_code == 0) && !keep_all_files) delete_dir_contents(TMP_DUMPED_ZIPS);

	if (exit_code == 0) TIME_OPERATION( "UnzipDecryptedZIPs", exit_code = UnzipDecryptedZIPs(TMP_DECRYPTED_ZIPS, OUT_FIRMWARE); );
	if ((exit_code == 0) && !keep_all_files) delete_dir_contents(TMP_DECRYPTED_ZIPS);

	if (exit_code == 0) {
		if (create_system) {
			if (exit_code == 0) exit_code = MoveSystemIMGFiles(OUT_FIRMWARE, TMP_DECRYPTED_SYSIMGS);

			if (exit_code == 0) {
				int i;
				int num_of_sysimg_dirs;
				struct dirent **entry_list;

				num_of_sysimg_dirs = versionsort_scandir(TMP_DECRYPTED_SYSIMGS, &entry_list, select_dirs);
				if (num_of_sysimg_dirs < 0) {
					exit_code = 2;
				}
				else if (num_of_sysimg_dirs == 0) {
					PRINT_ERROR("No system img directories found!");
					exit_code = 2;
				}
				else {
					for (i = 0; i < num_of_sysimg_dirs; i++) {
						int exit_code_tmp = 0;
						char * sysimg_name = entry_list[i]->d_name;

						char in_dir[PATH_MAX];
						char out_file[PATH_MAX];

						sprintf(in_dir, "%s/%s", TMP_DECRYPTED_SYSIMGS, sysimg_name);
						sprintf(out_file, "%s/%s%s", OUT_SYSTEM, sysimg_name, ".img");

						if (exit_code_tmp == 0) TIME_OPERATION( "Create system.img", exit_code_tmp = CreateSystemIMG(in_dir, out_file); );
						if ((exit_code_tmp == 0) && !keep_all_files) { delete_dir_contents(in_dir); remove(in_dir); }

						if (exit_code_tmp == 0) exit_code_tmp = TestSystemIMG(out_file);

						exit_code |= exit_code_tmp;
					}
					free_dirent_entry_list(entry_list, num_of_sysimg_dirs);
				}
				remove(TMP_DECRYPTED_SYSIMGS);
			}

			PRINT_TITLE("Adding boot.img to the system folder");
			std::string path_bootimg_file = find_file_from_pattern(OUT_FIRMWARE, BOOTIMG);
			if (path_bootimg_file.empty())
				path_bootimg_file = find_file_from_pattern(OUT_FIRMWARE, BOOTIMG_S);

			if (path_bootimg_file.empty()) {
				PRINT_ERROR("Couldn't find a %s or %s to copy to system folder.", BOOTIMG, BOOTIMG_S);
			}
			else if (!create_firmware) {
				PRINT_PROGRESS("Moving %s to %s", path_bootimg_file.c_str(), OUT_SYSTEM"/boot.img");
				move_file(path_bootimg_file.c_str(), OUT_SYSTEM"/boot.img");
			}
			else {
				PRINT_PROGRESS("Copying %s to %s", path_bootimg_file.c_str(), OUT_SYSTEM"/boot.img");
				copy_file(path_bootimg_file.c_str(), OUT_SYSTEM"/boot.img");
			}
		}

		PRINT_TITLE("Checking android-info.txt");
		path_android_info_file = find_file_from_pattern(OUT_FIRMWARE, ANDROIDINFO);
		if (!path_android_info_file.empty()) {
			if (!info.modelid.empty() || !info.mainver.empty())
				PRINT_INFO("Updating RUU Info from: %s", path_android_info_file.c_str());
			else
				PRINT_INFO("Information extracted from %s:", path_android_info_file.c_str());

			info = Parse_Android_Info(path_android_info_file.c_str());
			if (!info.modelid.empty()) PRINT_INFO("    INFO: RUU modelid: %s", info.modelid.c_str());
			if (!info.mainver.empty()) PRINT_INFO("    INFO: RUU mainver: %s", info.mainver.c_str());
		}
		else if (!info.modelid.empty() || !info.mainver.empty())
			PRINT_INFO("Couldn't find suitable android-info.txt file. Using previous info from RUU.EXE");
		else
			PRINT_INFO("Couldn't find suitable android-info.txt file. MID and RUU version are not known!");

		PRINT_TITLE("Checking keyfile state");
		if (ruuveal_device.empty()) {
			if (access("tmp/use_keyfile.bin", F_OK) == 0) {
				int res;

				res = Check_If_New_Keyfile("tmp/use_keyfile.bin", full_path_to_keys.c_str());

				if (res > 1)
					PRINT_ERROR("in Check_If_New_Keyfile (res=%i)", res);
				else if (res == 0) {
					PRINT_PROGRESS("Keyfile used already matches one in the keyfiles folder.");
					delete_file("tmp/use_keyfile.bin");
				}
				else {
					// move and rename keyfile
					std::string path_keyfile_file = info.modelid.substr(0, 4) + "_keyfile_" + info.mainver + ".bin";
					PRINT_PROGRESS("Moving keyfile to %s", path_keyfile_file.c_str());
					move_file("tmp/use_keyfile.bin", path_keyfile_file.c_str());

					PRINT_INFO("");
					PRINT_INFO("INFO: the keyfile '%s' generated appears to be new,", path_keyfile_file.c_str());

					int keyfile_uploaded = 0;
					if (!allow_upload)
						PRINT_INFO("      You have opted to disable keyfile uploads ");
					else if (Upload_Keyfile(path_keyfile_file.c_str()) == 0)
						keyfile_uploaded = 1;

					if (!keyfile_uploaded) {
						PRINT_INFO("      please consider sharing/uploading it, so it can be included in future");
						PRINT_INFO("      releases of this tool, at:");
						PRINT_INFO("http://forum.xda-developers.com/chef-central/android/tool-universal-htc-ruu-rom-decryption-t3382928");
						PRINT_INFO("");
						PRINT_INFO("Or run the tool with the '--sync-keyfiles' option");
					}
				}
			}
			else
				PRINT_PROGRESS("Unencrypted RUU, no keyfile was needed.");
			//printf("modelid='%s' ver='%s' keyfile='%s'", info.modelid.c_str(), info.mainver.c_str(), path_keyfile_file.c_str());
		}
		else {
			PRINT_PROGRESS("No keyfile was generated because ruuveal's built in '%s' device-key was used.", ruuveal_device.c_str());
		}
	}

	if (create_sd_zip && !info.modelid.empty()) {
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

	PRINT_INFO("");
	std::string full_path_to_final_out;
	full_path_to_final_out = full_path_to_wrk;

	if (!info.modelid.empty()) {
		PRINT_INFO("INFO: RUU modelid: %s", info.modelid.c_str());
		full_path_to_final_out += "_" + info.modelid.substr(0, 4);
	}
	if (!info.mainver.empty()) {
		PRINT_INFO("INFO: RUU mainver: %s", info.mainver.c_str());
		full_path_to_final_out += "_" + info.mainver;
	}
	PRINT_INFO("");

	if (full_path_to_wrk != full_path_to_final_out) {
		if (access(full_path_to_final_out.c_str(), R_OK) == 0) {
			PRINT_INFO("Folder '%s' already exists! Keeping files in OUT folder.", full_path_to_final_out.c_str());
			PRINT_INFO("");
			full_path_to_final_out = full_path_to_wrk;
		}
		else if (rename(full_path_to_wrk.c_str(), full_path_to_final_out.c_str())) {
			PRINT_INFO("Failed to rename '%s' to '%s' (%s) !", full_path_to_wrk.c_str(), full_path_to_final_out.c_str(), strerror(errno));
			PRINT_INFO("");
			full_path_to_final_out = full_path_to_wrk;
		}
	}

	Timer_ToolEnd();

	//Finished:
	if (exit_code == 0)
		PRINT_FINISHED("Successfully extracted zip files to\n             '%s'", full_path_to_final_out.c_str());
	else
		PRINT_FINISHED("Tool has finished but there was an error, please\n          check the console output and your OUT folder\n             '%s'", full_path_to_final_out.c_str());

	PRINT_INFO("");

	change_dir(full_path_to_final_out);
	write_log_file("RUU_Decrypt_LOG-" + info.modelid + "_" + info.mainver + "_" + Current_DateTime() + ".txt");

	change_dir(path_cur.c_str());

	press_enter_to_exit();

	return exit_code;
}
