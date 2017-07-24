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

#ifndef _TIME_FUNCTIONS_H
#define _TIME_FUNCTIONS_H


#include <string>

std::string Current_DateTime(void);

void Timer_OperationStart(void);
void Timer_OperationEnd(const std::string operation_name);

void Timer_ToolStart(void);
void Timer_ToolEnd(void);


// Yes I know this is horrible
#define TIME_OPERATION(OPERATION_NAME, ...) do { Timer_OperationStart(); __VA_ARGS__; Timer_OperationEnd(OPERATION_NAME); } while (0)


#endif // _TIME_FUNCTIONS_H
