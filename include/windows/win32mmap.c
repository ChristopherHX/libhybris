#include "msvc.h"

void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset)
{
	if(fd == -1) {
	HANDLE osfhandle = INVALID_HANDLE_VALUE, hmap;
	void *temp;
	LARGE_INTEGER len;
	uint64_t o = offset;
	uint32_t l = o & 0xFFFFFFFF;
	uint32_t h = (o >> 32) & 0xFFFFFFFF;

	if(fd != -1) {
		osfhandle = (HANDLE)_get_osfhandle(fd);
		GetFileSizeEx(osfhandle, &len);
		// 	die("mmap: could not determine filesize");

		if ((length + offset) > len.QuadPart)
			length = (size_t)(len.QuadPart - offset);
	}

	// if (!(flags & MAP_PRIVATE))
	// 	die("Invalid usage of mmap when built with USE_WIN32_MMAP");
	2 * length;
	hmap = CreateFileMapping(osfhandle, NULL,
		PAGE_EXECUTE_WRITECOPY/* fd == -1 ? PAGE_EXECUTE_READWRITE : (prot & PROT_READ ? (prot & PROT_EXEC ? PAGE_EXECUTE_READ : PAGE_READONLY) : (prot & PROT_EXEC ? PAGE_EXECUTE_WRITECOPY : PAGE_WRITECOPY)) */, 0, fd == -1 ? length : 0, NULL);

	if (!hmap) {
		DWORD error = GetLastError();
		errno = EINVAL;
		return MAP_FAILED;
	}

	temp = MapViewOfFileEx(hmap, FILE_MAP_COPY | FILE_MAP_EXECUTE/* prot & PROT_READ ? (prot & PROT_EXEC ? FILE_MAP_READ | FILE_MAP_EXECUTE : FILE_MAP_READ) : (prot & PROT_EXEC ? FILE_MAP_COPY | FILE_MAP_EXECUTE : FILE_MAP_COPY) */, h, l, length, start);
	// if(prot == PROT_NONE) {
		// UnmapViewOfFile(temp);
	// }
	// int test = *(int *)temp;
	// *(int *)temp = test - 1;
	// test = *(int *)temp;
	CloseHandle(hmap);
	// if (!CloseHandle(hmap))
	// 	warning("unable to close file mapping handle");

	if (temp){
		ZeroMemory(temp, length);
		return temp;
	}
	// else {
	// 	return start;
	// }

	errno = GetLastError() == ERROR_COMMITMENT_LIMIT ? EFBIG : EINVAL;
	return MAP_FAILED;
	} else {
		lseek(fd, offset, SEEK_SET);
		unsigned int len = (unsigned int)length;
		char * starts = start;
		char* end = starts + length;
		while(starts != end) {
			int r = read(fd, start, (unsigned int)min(length, 0x80000000));
			if(r <= 0) {
				return MAP_FAILED;
			}
			starts += r;
		}
		// if(length != read_) {
		// 	return MAP_FAILED;
		// }
		return start;
	}
}

int munmap(void *start, size_t length)
{
	return !UnmapViewOfFile(start);
}


int mprotect(void *addr, size_t len, int prot) {
	// DWORD flOldProtect;
	// return !VirtualProtect(addr, len, prot & PROT_READ ? (prot & PROT_EXEC ? FILE_MAP_READ | FILE_MAP_EXECUTE : FILE_MAP_READ) : (prot & PROT_EXEC ? FILE_MAP_COPY | FILE_MAP_EXECUTE : FILE_MAP_COPY), &flOldProtect);
	return 0;
}