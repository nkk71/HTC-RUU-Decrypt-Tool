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
#include <time.h>

#include <string>
#include <ctime>


#include "Common.h"

#include "Time_Functions.h"

std::string Current_DateTime(void)
{
#if defined(__ANDROID__)
	if (!getenv("TZ")) {
		FILE * fp = popen("getprop persist.sys.timezone", "r");
		if (fp) {
			char output[100];
			if (fgets(output, sizeof(output), fp)) {
				output[strlen(output)-1] = 0;
				setenv("TZ", output, 0);
			}
			pclose(fp);
		}
	}
#endif

	std::time_t rawtime;
	std::tm* timeinfo;
	char buffer[25];

	std::time(&rawtime);
	timeinfo = std::localtime(&rawtime);

	std::strftime(buffer, sizeof(buffer),"%Y-%m-%d_%H%M%S", timeinfo);
	return buffer;
}


static timespec timespec_diff(timespec& start, timespec& end)
{
	timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

static timespec GetTime(void)
{
	timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return now;
}

static std::string OperationTook(timespec startTime, timespec endTime)
{
	timespec diff = timespec_diff(startTime, endTime);
	// Consider rounding to the nearest ms and sec if need be
	//~ int millisec = lrint(tv.tv_usec/1000.0); // Round to nearest millisec
	//~ if (millisec>=1000) { // Allow for rounding up to nearest second
		//~ millisec -=1000;
		//~ diff.tv_sec++;
	//~ }
	//~ //printf("%lld.%ld\n", (long long)diff.tv_sec, diff.tv_nsec);
	//~ char buffer[30];
//~ strftime(buffer, 26, "%Y:%m:%d %H:%M:%S", diff);
  //~ printf("%s.%03d\n", buffer, millisec);
	
	int msec = diff.tv_nsec / 1000 / 1000;
	int mins = diff.tv_sec / 60;
	int secs = diff.tv_sec - (mins * 60);
	char buffer[200];
	if (mins == 0)
		snprintf(buffer, sizeof(buffer), "%d.%03d seconds.\n", secs, msec);
	else if (mins == 1)
		snprintf(buffer, sizeof(buffer), "%d minute %d.%03d seconds.\n", mins, secs, msec);
	else
		snprintf(buffer, sizeof(buffer), "%d minutes %d.%03d seconds.\n", mins, secs, msec);
	return buffer;
}


static timespec Timer_1start; // Entire run
static timespec Timer_2start; // Submodule run

void Timer_OperationStart(void)
{
	Timer_2start = GetTime();
}

void Timer_OperationEnd(const std::string operation_name)
{
	//~ "$BINARYNAME process completion time: x minute(s), y second(s)."
	PRINT_INFO("%s took %s", operation_name.c_str(), OperationTook(Timer_2start, GetTime()).c_str());
}

void Timer_ToolStart(void)
{
	Timer_1start = GetTime();
}

void Timer_ToolEnd(void)
{
	PRINT_INFO("Overall process completion time: %s", OperationTook(Timer_1start, GetTime()).c_str());
}
