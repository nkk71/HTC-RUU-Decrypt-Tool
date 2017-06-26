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

#include <curl/curl.h>

#define KEYFILE_SIZE 96
#define USERAGENT "ruu_decrypt_tool" // "curl/7.53.0-DEV"
#define FTP_URL "ftp://ruu_decrypt_tool:nkk71cptb@shadow-projects.root.sx/keyfiles"


#define PROGRESS_RESET do {  \
	if (dot_counter)         \
		printf("\n");        \
	dot_counter = 0;         \
} while(0)

#define PROGRESS_INCR do {   \
	printf(".");             \
	dot_counter++;           \
	if (dot_counter > 15) {  \
		printf("\n");        \
		dot_counter = 0;     \
	}                        \
	fflush(stdout);          \
} while(0)


int count;
int verbose = 0;
int print_debug_info = 0;
int dot_counter;

struct callback_data {
  FILE *output;
};

static long file_is_coming(struct curl_fileinfo *finfo, struct callback_data *data, int remains)
{
	static int first_call = 1;

	if (first_call) {
		printf("Found %d keyfiles\n", remains);
		first_call = 0;
	}

	if (verbose) {
		printf("%3d %30s %5luB ...", remains, finfo->filename, (unsigned long)finfo->size);
		fflush(stdout);
	}

	if (finfo->filetype == CURLFILETYPE_FILE) {
		if (finfo->size != KEYFILE_SIZE || access(finfo->filename, F_OK) == 0) {
			// file not the correct size for a keyfile or already exists
			if (verbose)
				printf("SKIPPED\n");
			return CURL_CHUNK_BGN_FUNC_SKIP;
		}

		// Download File
		if (!verbose) {
			printf("%3d %30s %5luB ...", remains, finfo->filename, (unsigned long)finfo->size);
			fflush(stdout);
		}

		data->output = fopen(finfo->filename, "wb");
		if(!data->output) {
			printf("FAILED\n");
			return CURL_CHUNK_BGN_FUNC_FAIL;
		}
	}
	return CURL_CHUNK_BGN_FUNC_OK;
}

static long file_is_downloaded(struct callback_data *data)
{
	if(data->output) {
		printf("DOWNLOADED\n");
		fclose(data->output);
		data->output = 0x0;
		count++;
	}
	return CURL_CHUNK_END_FUNC_OK;
}

static size_t write_it(char *buff, size_t size, size_t nmemb, struct callback_data *cb_data)
{
	struct callback_data *data = cb_data;
	size_t written = 0;

	if(data->output)
		written = fwrite(buff, size, nmemb, data->output);
	else
		/* listing output */
		written = fwrite(buff, size, nmemb, stdout);

	return written;
}

int download_new(void)
{
	CURL *curl;
	CURLcode res;
	struct callback_data data = { 0 };
	count = 0;

	// global initialization
	res = curl_global_init(CURL_GLOBAL_ALL);
	if(res) {
		printf("libcurl: global_init error=%d (%s)!\n", res, curl_easy_strerror(res));
		return -1;
	}

	// initialization of easy handle
	curl = curl_easy_init();
	if(!curl) {
		printf("libcurl: easy_init error\n");
		curl_global_cleanup();
		return -1;
	}

	printf("Connecting...\n");

	// set up basic curl info
	curl_easy_setopt(curl, CURLOPT_USERAGENT, USERAGENT);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
	curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
	if (print_debug_info)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	// set callbacks for reading from ftp and writing locally
	curl_easy_setopt(curl, CURLOPT_CHUNK_BGN_FUNCTION, file_is_coming);     // callback is called before download of concrete file started
	curl_easy_setopt(curl, CURLOPT_CHUNK_END_FUNCTION, file_is_downloaded); // callback is called after data from the file have been transferred
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_it);                // this callback will write contents into files

	// put transfer data into callbacks
	curl_easy_setopt(curl, CURLOPT_CHUNK_DATA, &data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);

	// set ftp URL and wildcard for '*.bin' files only
	curl_easy_setopt(curl, CURLOPT_WILDCARDMATCH, 1L);
	curl_easy_setopt(curl, CURLOPT_URL, FTP_URL "/*.bin");

	res = curl_easy_perform(curl);

	curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (res == CURLE_OK) {
		if (count == 0)
			printf("Your keyfiles are up to date.\n");
		else
			printf("Downloaded %d new keyfiles.\n", count);
		return 0;
	}
	else {
		if (count == 0)
			printf("Transfer error %d (%s)!\n", res, curl_easy_strerror(res));
		else
			printf("Downloaded %d new keyfiles, but ended in error %d (%s)!\n", count, res, curl_easy_strerror(res));
		return -1;
	}
}


static size_t throw_away(void *ptr, size_t size, size_t nmemb, void *data)
{
	(void)ptr;
	(void)data;
	/* we are not interested in the headers itself,
	 so we only return the size we would have saved ... */
	return (size_t)(size * nmemb);
}


/*
 * upload_keyfile
 * ------------------------------------------------
 *
 * exit codes:
 *  -1 -> Connection Error
 *   0 -> file uploaded
 *   1 -> file already exists on server
 *   2 -> open error
 *   3 -> incorrect filesize
 *   4 -> upload error
 */
int upload_keyfile(CURL *curl, const char *path_keyfile)
{
	CURLcode res;
	char ftp_file[256];
	int exit_code = 0;

	const char *filename = strrchr(path_keyfile, '/');
	if (filename)
		filename++;
	else
		filename = path_keyfile;

	FILE *fp = fopen(path_keyfile, "rb");
	if (!fp) {
		printf("Could not open local file '%s'!\n", filename);
		return 2;
	}

	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (size != KEYFILE_SIZE) {
		fclose(fp);
		printf("Local file '%s' has an incorrect size for a keyfile!\n", filename);
		return 3;
	}

	snprintf(ftp_file, sizeof(ftp_file), "%s/%s", FTP_URL, filename);
	curl_easy_setopt(curl, CURLOPT_URL, ftp_file);

	// check if file exists but don't print anything to stdout
	// (by checking correct keyfile size, if it's not correct size overwrite)
	curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
	curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, throw_away);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, throw_away);

	res = curl_easy_perform(curl);

	curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
	curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, NULL);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);

	if (res == CURLE_OK) {
		double filesize = 0.0;
		res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &filesize);
		//printf("size=%0.0f\n", filesize);
		if (filesize == KEYFILE_SIZE) {
			if (verbose)
				printf("File '%s' already exists, not uploading\n", filename);
			else if (!print_debug_info) {
				PROGRESS_INCR;
			}
			exit_code = 1;
		}
		else {
			PROGRESS_RESET;
			printf("Uploading '%s'...", filename);
			fflush(stdout);
			if (print_debug_info)
				printf("\n");

			curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
			curl_easy_setopt(curl, CURLOPT_INFILESIZE, (long)KEYFILE_SIZE);
			curl_easy_setopt(curl, CURLOPT_READDATA, fp);

			res = curl_easy_perform(curl);

			if (res == CURLE_OK) {
				printf("UPLOADED\n");
				exit_code = 0;
			}
			else {
				printf("upload error %d (%s)!\n", res, curl_easy_strerror(res));
				exit_code = 4;
			}
		}
	}
	else {
		PROGRESS_RESET;
		printf("Connection error %d (%s)!\n", res, curl_easy_strerror(res));
		exit_code = -1;
	}

	fclose(fp);

	return exit_code;
}

int upload_files(const char *path_keyfile)
{
	PROGRESS_RESET;

	CURL *curl;
	CURLcode res;
	int ret;
	int count = 0;

	// global initialization
	res = curl_global_init(CURL_GLOBAL_ALL);
	if(res) {
		printf("libcurl: global_init error=%d (%s)!\n", res, curl_easy_strerror(res));
		return -1;
	}

	// initialization of easy handle
	curl = curl_easy_init();
	if(!curl) {
		printf("libcurl: easy_init error\n");
		curl_global_cleanup();
		return -1;
	}

	printf("Connecting...\n");

	// set up basic curl info
	curl_easy_setopt(curl, CURLOPT_USERAGENT, USERAGENT);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
	curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
	if (print_debug_info)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);


	if (path_keyfile) {
		// single file
		ret = upload_keyfile(curl, path_keyfile);

		if (ret == 0)
			count++;
		else if (ret == 1) // no error, file already exists
			ret = 0;
	}
	else {
		// entire folder
		int err = 0;
		const char *filename;
		const char *extension;

		DIR *dp = opendir(".");
		struct dirent *de;

		while ((de = readdir(dp))) {

			if (de->d_type != DT_REG)
				continue;

			filename = de->d_name;
			extension = strrchr(filename, '.');
			if (!extension || strcmp(extension, ".bin") != 0)
				continue;

			ret = upload_keyfile(curl, filename);
			if (ret < 0) {
				err = 1;
				break;
			}
			else if (ret == 0)
				count++;
			else if (ret == 4)
				err = 1;
		}
		closedir(dp);

		if (err)
			ret = -1;
		else
			ret = 0;
	}

	curl_easy_cleanup(curl);
	curl_global_cleanup();

	PROGRESS_RESET;

	if (ret == 0) {
		if (count > 0)
			printf("Uploaded %d new keyfiles.\n", count);
		return 0;
	}
	else {
		if (count == 0)
			printf("Transfer error!\n");
		else
			printf("Uploaded %d new keyfiles, but ended in error!\n", count);
		return -1;
	}
}


int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--download-new") == 0)
		return download_new();

	else if (argc == 2 && strcmp(argv[1], "--upload-new") == 0)
		return upload_files(NULL);

	else if (argc == 3 && strcmp(argv[1], "--upload-new") == 0)
		return upload_files(argv[2]);

	else {
		printf("\n");
		printf("\n");
		printf("Usage Information\n");
		printf("-----------------\n");
		printf("* Usage 1: %s --download-new\n", argv[0]);
		printf("\n");
		printf("  Downloads all keyfiles to the current directory\n");
		printf("  (Will not overwrite any locally existing files)\n");
		printf("----------------------------------------------------\n");
		printf("* Usage 2: %s --upload-new <keyfile>\n", argv[0]);
		printf("\n");
		printf("  Uploads <keyfile>\n");
		printf("----------------------------------------------------\n");
		printf("* Usage 3: %s --upload-new\n", argv[0]);
		printf("\n");
		printf("  Uploads all keyfiles from the current directory\n");
		printf("----------------------------------------------------\n");
		printf("\n");
	}

	return -1;
}
