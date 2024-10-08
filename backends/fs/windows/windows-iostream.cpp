/* ScummVM - Graphic Adventure Engine
 *
 * ScummVM is the legal property of its developers, whose names
 * are too numerous to list here. Please refer to the COPYRIGHT
 * file distributed with this source distribution.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "backends/platform/sdl/win32/win32_wrapper.h"

// Include this after windows.h so we don't get a warning for redefining ARRAYSIZE
#include "backends/fs/windows/windows-iostream.h"

WindowsIoStream::WindowsIoStream(void *handle) :
		StdioStream(handle) {
}

bool WindowsIoStream::moveFile(const Common::String &src, const Common::String &dst) {
	TCHAR *tSrc = Win32::stringToTchar(src);
	TCHAR *tDst = Win32::stringToTchar(dst);

	DWORD ret = MoveFileExFunc(tSrc, tDst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);

	free(tSrc);
	free(tDst);

	if (ret == ERROR_SUCCESS) {
		return true;
	}
	if (ret != ERROR_CALL_NOT_IMPLEMENTED) {
		return false;
	}

	// Fall back on possibily unsafe unlink/rename
	return StdioStream::moveFile(src, dst);
}

