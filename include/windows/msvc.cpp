#include "msvc.h"
#undef stat
#include <string>
#include <cvt/utf8_utf16>
#include <fcntl.h>
#include "utime.h"
#include <signal.h>
#include <cstdio>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include <regex>
#include <filesystem>
#include <WinUser.h>
#include <iostream>
#include <VersionHelpers.h>

	int err_win_to_posix(DWORD winerr)
	{
		int error = ENOSYS;
		switch (winerr) {
		case ERROR_ACCESS_DENIED: error = EACCES; break;
		case ERROR_ACCOUNT_DISABLED: error = EACCES; break;
		case ERROR_ACCOUNT_RESTRICTION: error = EACCES; break;
		case ERROR_ALREADY_ASSIGNED: error = EBUSY; break;
		case ERROR_ALREADY_EXISTS: error = EEXIST; break;
		case ERROR_ARITHMETIC_OVERFLOW: error = ERANGE; break;
		case ERROR_BAD_COMMAND: error = EIO; break;
		case ERROR_BAD_DEVICE: error = ENODEV; break;
		case ERROR_BAD_DRIVER_LEVEL: error = ENXIO; break;
		case ERROR_BAD_EXE_FORMAT: error = ENOEXEC; break;
		case ERROR_BAD_FORMAT: error = ENOEXEC; break;
		case ERROR_BAD_LENGTH: error = EINVAL; break;
		case ERROR_BAD_PATHNAME: error = ENOENT; break;
		case ERROR_BAD_PIPE: error = EPIPE; break;
		case ERROR_BAD_UNIT: error = ENODEV; break;
		case ERROR_BAD_USERNAME: error = EINVAL; break;
		case ERROR_BROKEN_PIPE: error = EPIPE; break;
		case ERROR_BUFFER_OVERFLOW: error = ENAMETOOLONG; break;
		case ERROR_BUSY: error = EBUSY; break;
		case ERROR_BUSY_DRIVE: error = EBUSY; break;
		case ERROR_CALL_NOT_IMPLEMENTED: error = ENOSYS; break;
		case ERROR_CANNOT_MAKE: error = EACCES; break;
		case ERROR_CANTOPEN: error = EIO; break;
		case ERROR_CANTREAD: error = EIO; break;
		case ERROR_CANTWRITE: error = EIO; break;
		case ERROR_CRC: error = EIO; break;
		case ERROR_CURRENT_DIRECTORY: error = EACCES; break;
		case ERROR_DEVICE_IN_USE: error = EBUSY; break;
		case ERROR_DEV_NOT_EXIST: error = ENODEV; break;
		case ERROR_DIRECTORY: error = EINVAL; break;
		case ERROR_DIR_NOT_EMPTY: error = ENOTEMPTY; break;
		case ERROR_DISK_CHANGE: error = EIO; break;
		case ERROR_DISK_FULL: error = ENOSPC; break;
		case ERROR_DRIVE_LOCKED: error = EBUSY; break;
		case ERROR_ENVVAR_NOT_FOUND: error = EINVAL; break;
		case ERROR_EXE_MARKED_INVALID: error = ENOEXEC; break;
		case ERROR_FILENAME_EXCED_RANGE: error = ENAMETOOLONG; break;
		case ERROR_FILE_EXISTS: error = EEXIST; break;
		case ERROR_FILE_INVALID: error = ENODEV; break;
		case ERROR_FILE_NOT_FOUND: error = ENOENT; break;
		case ERROR_GEN_FAILURE: error = EIO; break;
		case ERROR_HANDLE_DISK_FULL: error = ENOSPC; break;
		case ERROR_INSUFFICIENT_BUFFER: error = ENOMEM; break;
		case ERROR_INVALID_ACCESS: error = EACCES; break;
		case ERROR_INVALID_ADDRESS: error = EFAULT; break;
		case ERROR_INVALID_BLOCK: error = EFAULT; break;
		case ERROR_INVALID_DATA: error = EINVAL; break;
		case ERROR_INVALID_DRIVE: error = ENODEV; break;
		case ERROR_INVALID_EXE_SIGNATURE: error = ENOEXEC; break;
		case ERROR_INVALID_FLAGS: error = EINVAL; break;
		case ERROR_INVALID_FUNCTION: error = ENOSYS; break;
		case ERROR_INVALID_HANDLE: error = EBADF; break;
		case ERROR_INVALID_LOGON_HOURS: error = EACCES; break;
		case ERROR_INVALID_NAME: error = EINVAL; break;
		case ERROR_INVALID_OWNER: error = EINVAL; break;
		case ERROR_INVALID_PARAMETER: error = EINVAL; break;
		case ERROR_INVALID_PASSWORD: error = EPERM; break;
		case ERROR_INVALID_PRIMARY_GROUP: error = EINVAL; break;
		case ERROR_INVALID_SIGNAL_NUMBER: error = EINVAL; break;
		case ERROR_INVALID_TARGET_HANDLE: error = EIO; break;
		case ERROR_INVALID_WORKSTATION: error = EACCES; break;
		case ERROR_IO_DEVICE: error = EIO; break;
		case ERROR_IO_INCOMPLETE: error = EINTR; break;
		case ERROR_LOCKED: error = EBUSY; break;
		case ERROR_LOCK_VIOLATION: error = EACCES; break;
		case ERROR_LOGON_FAILURE: error = EACCES; break;
		case ERROR_MAPPED_ALIGNMENT: error = EINVAL; break;
		case ERROR_META_EXPANSION_TOO_LONG: error = E2BIG; break;
		case ERROR_MORE_DATA: error = EPIPE; break;
		case ERROR_NEGATIVE_SEEK: error = ESPIPE; break;
		case ERROR_NOACCESS: error = EFAULT; break;
		case ERROR_NONE_MAPPED: error = EINVAL; break;
		case ERROR_NOT_ENOUGH_MEMORY: error = ENOMEM; break;
		case ERROR_NOT_READY: error = EAGAIN; break;
		case ERROR_NOT_SAME_DEVICE: error = EXDEV; break;
		case ERROR_NO_DATA: error = EPIPE; break;
		case ERROR_NO_MORE_SEARCH_HANDLES: error = EIO; break;
		case ERROR_NO_PROC_SLOTS: error = EAGAIN; break;
		case ERROR_NO_SUCH_PRIVILEGE: error = EACCES; break;
		case ERROR_OPEN_FAILED: error = EIO; break;
		case ERROR_OPEN_FILES: error = EBUSY; break;
		case ERROR_OPERATION_ABORTED: error = EINTR; break;
		case ERROR_OUTOFMEMORY: error = ENOMEM; break;
		case ERROR_PASSWORD_EXPIRED: error = EACCES; break;
		case ERROR_PATH_BUSY: error = EBUSY; break;
		case ERROR_PATH_NOT_FOUND: error = ENOENT; break;
		case ERROR_PIPE_BUSY: error = EBUSY; break;
		case ERROR_PIPE_CONNECTED: error = EPIPE; break;
		case ERROR_PIPE_LISTENING: error = EPIPE; break;
		case ERROR_PIPE_NOT_CONNECTED: error = EPIPE; break;
		case ERROR_PRIVILEGE_NOT_HELD: error = EACCES; break;
		case ERROR_READ_FAULT: error = EIO; break;
		case ERROR_SEEK: error = EIO; break;
		case ERROR_SEEK_ON_DEVICE: error = ESPIPE; break;
		case ERROR_SHARING_BUFFER_EXCEEDED: error = ENFILE; break;
		case ERROR_SHARING_VIOLATION: error = EACCES; break;
		case ERROR_STACK_OVERFLOW: error = ENOMEM; break;
		case ERROR_SWAPERROR: error = ENOENT; break;
		case ERROR_TOO_MANY_MODULES: error = EMFILE; break;
		case ERROR_TOO_MANY_OPEN_FILES: error = EMFILE; break;
		case ERROR_UNRECOGNIZED_MEDIA: error = ENXIO; break;
		case ERROR_UNRECOGNIZED_VOLUME: error = ENODEV; break;
		case ERROR_WAIT_NO_CHILDREN: error = ECHILD; break;
		case ERROR_WRITE_FAULT: error = EIO; break;
		case ERROR_WRITE_PROTECT: error = EROFS; break;
		}
		return error;
	}

#define utf8towcs(_str) _str != NULL ? std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(_str).data() : NULL

#define wcstoutf8(_wstr) (_wstr != NULL ? std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().to_bytes(_wstr) : std::string())

const char * cwcstoutf8(wchar_t * in)
{
	return strdup((wcstoutf8(in)).data());
}

std::wstring getPath(const char * path) {
	auto wpath = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(path);
	for(auto&c: wpath) {
		if(c == '/') c = '\\';
	}
	return wpath;
}

int _wlstat(const wchar_t * path, struct stat * status)
{
	HANDLE link;
	if ((link = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL)) != INVALID_HANDLE_VALUE) {
		int fd;
		if ((fd = _open_osfhandle((intptr_t)link, _O_BINARY)) != -1)
		{
			int ret = fstat(fd, status);
			if (ret == 0 && (status->st_mode & S_IFMT) == S_IFMT)
			{
				BY_HANDLE_FILE_INFORMATION info;
				GetFileInformationByHandle(link, &info);
				if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == FILE_ATTRIBUTE_REPARSE_POINT) {
					status->st_mode &= ~S_IFMT;
					status->st_mode |= S_IFLNK;
				}
			}
			_close(fd);
			return ret;
		} else {
			errno = EBADF;
		}
		CloseHandle(link);
	} else {
		errno = ENOENT;
	}
	return -1;
}

int lstat(const char * path, struct stat * status)
{
	return _wlstat(getPath(path).data(), status);
}

int msvc_stat(const char * path, struct stat * status)
{
	return _wstat(getPath(path).data(), (struct _stat64i32*)status);
}

#undef unlink
int msvc_unlink(const char *pathname)
{
	auto name = getPath(pathname);
	SetFileAttributesW(name.data(), GetFileAttributesW(name.data()) & ~FILE_ATTRIBUTE_READONLY);
	return _wunlink(name.data());
}

#undef rmdir
int msvc_rmdir(const char *pathname)
{
	return _wrmdir(getPath(pathname).data());
}

#undef mkdir
int msvc_mkdir(const char *path, int mode)
{
	return _wmkdir(getPath(path).data());
}

#undef open
int msvc_open(const char *filename, int oflags, ...)
{
	va_list args;
	int mode;
	int fd;
	va_start(args, oflags);
	mode = va_arg(args, int);
	va_end(args);
	if (filename && !strcmp(filename, "/dev/null"))
		filename = "nul";
	fd = _wopen(getPath(filename).data(), oflags, mode);
	return fd;
}

static BOOL WINAPI ctrl_ignore(DWORD type)
{
	return TRUE;
}

#undef fgetc
int msvc_fgetc(FILE *stream)
{
	int ch;
	if (!isatty(_fileno(stream)))
		return fgetc(stream);

	SetConsoleCtrlHandler(ctrl_ignore, TRUE);
	while (1) {
		ch = fgetc(stream);
		if (ch != EOF || GetLastError() != ERROR_OPERATION_ABORTED)
			break;

		/* Ctrl+C was pressed, simulate SIGINT and retry */
		msvc_raise(SIGINT);
	}
	SetConsoleCtrlHandler(ctrl_ignore, FALSE);
	return ch;
}

#undef fopen
FILE *msvc_fopen(const char *filename, const char *otype)
{
	if (filename && !strcmp(filename, "/dev/null"))
		filename = "nul";
	return _wfopen(getPath(filename).data(), utf8towcs(otype));
}

#undef freopen
FILE *msvc_freopen(const char *filename, const char *otype, FILE *stream)
{
	if (filename && !strcmp(filename, "/dev/null"))
		filename = "nul";
	return _wfreopen(getPath(filename).data(), utf8towcs(otype), stream);
}

#undef access
int msvc_access(const char *filename, int mode)
{
	return _waccess(getPath(filename).data(), mode);
}

#undef chdir
int msvc_chdir(const char *dirname)
{
	return _wchdir(getPath(dirname).data());
}

#undef chmod
int msvc_chmod(const char *filename, int mode)
{
	return _wchmod(getPath(filename).data(), mode);
}

/*
* The unit of FILETIME is 100-nanoseconds since January 1, 1601, UTC.
* Returns the 100-nanoseconds ("hekto nanoseconds") since the epoch.
*/
static inline long long filetime_to_hnsec(const FILETIME *ft)
{
	long long winTime = ((long long)ft->dwHighDateTime << 32) + ft->dwLowDateTime;
	/* Windows to Unix Epoch conversion */
	return winTime - 116444736000000000LL;
}

static inline void time_t_to_filetime(time_t t, FILETIME *ft)
{
	long long winTime = t * 10000000LL + 116444736000000000LL;
	ft->dwLowDateTime = winTime;
	ft->dwHighDateTime = winTime >> 32;
}

#undef utime
int msvc_utime(const char *file_name, const struct utimbuf *times)
{
	FILETIME mft, aft;
	int rc;
	HANDLE fh = CreateFileW(getPath(file_name).data(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (times) {
		time_t_to_filetime(times->modtime, &mft);
		time_t_to_filetime(times->actime, &aft);
	}
	else {
		GetSystemTimeAsFileTime(&mft);
		aft = mft;
	}
	if (!SetFileTime(fh, NULL, &aft, &mft)) {
		errno = EINVAL;
		rc = -1;
	}
	else
		rc = 0;
	CloseHandle(fh);
	return rc;
}

unsigned int sleep(unsigned int seconds)
{
	Sleep(seconds * 1000);
	return 0;
}

#undef mktemp
char *msvc_mktemp(char *templat)
{
	auto wtemplate = getPath(templat);
	if (!_wmktemp((wchar_t*)wtemplate.data()))
		return NULL;
	WideCharToMultiByte(CP_UTF8, 0, wtemplate.data(), -1, templat, strlen(templat) + 1, NULL, NULL);
	return templat;
}

int mkstemp(char *templat)
{
	auto wtemplate = getPath(templat);
	wchar_t *filename = _wmktemp((wchar_t*)wtemplate.data());
	if (filename == NULL)
		return -1;
	return _wopen(filename, O_RDWR | O_CREAT, 0600);
}

int gettimeofday(struct timeval *tv, void *tz)
{
	FILETIME ft;
	long long hnsec;

	GetSystemTimeAsFileTime(&ft);
	hnsec = filetime_to_hnsec(&ft);
	tv->tv_sec = hnsec / 10000000;
	tv->tv_usec = (hnsec % 10000000) / 10;
	return 0;
}

struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
	/* gmtime() in MSVCRT.DLL is thread-safe, but not reentrant */
	memcpy(result, gmtime(timep), sizeof(struct tm));
	return result;
}

struct tm *localtime_r(const time_t *timep, struct tm *result)
{
	/* localtime() in MSVCRT.DLL is thread-safe, but not reentrant */
	memcpy(result, localtime(timep), sizeof(struct tm));
	return result;
}

#undef getcwd
char *msvc_getcwd(char *pointer, int len)
{
	wchar_t * wpointer = new wchar_t[len];
	if (!_wgetcwd(wpointer, len))
		return NULL;
	WideCharToMultiByte(CP_UTF8, 0, wpointer, -1, pointer, len, NULL, NULL);
	delete[] wpointer;
	for(char * c = strchr(pointer, '\\'),* e = pointer + len; c && c != e && *c; c = strchr(c, '\\')) *c = '/';
	return pointer;
}

#undef getenv
struct ci_less
{
	// case-independent (ci) compare_less binary function
	struct nocase_compare
	{
		bool operator() (const unsigned char& c1, const unsigned char& c2) const {
			return tolower(c1) < tolower(c2);
		}
	};
	bool operator() (const std::string & s1, const std::string & s2) const {
		return std::lexicographical_compare
		(s1.begin(), s1.end(),   // source range
			s2.begin(), s2.end(),   // dest range
			nocase_compare());  // comparison
	}
};
std::unordered_map<std::string, std::string> env = {
	{ "TMPDIR", getenv("tmp")},
	{ "HOME", getenv("userprofile")}
};
const char *msvc_getenv(const char *_VarName)
{
	std::string & val = env[_VarName];
	if (val.empty() && (val = wcstoutf8(_wgetenv(utf8towcs(_VarName)))).empty())
	{
		return NULL;
	}
	return val.data();
}

#undef putenv
int msvc_putenv(const char *_EnvString)
{
	if (_EnvString)
	{
		const char* eq = strchr(_EnvString, '=');
		env[std::string(_EnvString, eq)] = std::string(eq + 1);
		return 0;
	}
	return -1;
}

int setenv(const char *name, const char *value, int replace)
{
	std::string & val = env[name];
	if (replace || (val.empty() && (val = wcstoutf8(_wgetenv(utf8towcs(name)))).empty()))
	{
		if (value != nullptr)
			val = value;
		else
			val.clear();
		return 0;
	}
	return -1;
}

int unsetenv(const char * name)
{
	return setenv(name, NULL, 1);
}

class __noconv {
public:
	inline std::wstring&& to_bytes(std::wstring&& str) {
		return std::move(str);
	}
};

// pseudo posix commandline parser
template<class T = char, class Converter = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>>
std::vector<std::basic_string<T>> CommandLineToArgv(const wchar_t * CmdLine, size_t maxargc = -1)
{
	wchar_t a;
	Converter converter;
	std::vector<std::basic_string<T>> argv;
	std::wregex sq(L"^((\\\\'|\\\\\\\\|[^'])*)'");
	std::wregex sqe(L"\\\\('|\\\\)'");
	std::wregex dq(L"^((\\\\\\\"|\\\\\\\\|[^\\\"])*)\\\"");
	std::wregex dqe(L"\\\\(\\\"|\\\\)");
	std::wregex br(L"^[^'\\\" ]+");
	std::basic_ostringstream<T> arg;
	int i = 0;
	std::basic_string<T> last;
	while( a = CmdLine[i] ) {
		switch(a) {
		case '\'':
		{
			std::wcmatch results;
			std::regex_search(&CmdLine[++i], results, sq);
			const auto & prefix = results[1];
			arg << converter.to_bytes(std::regex_replace(prefix.str(), sqe, L"$1"));
			i += prefix.length();
			break;
		}
		case '\"':
		{
			std::wcmatch results;
			std::regex_search(&CmdLine[++i], results, dq);
			const auto & prefix = results[1];
			arg << converter.to_bytes(std::regex_replace(prefix.str(), dqe, L"$1"));
			i += prefix.length();
			break;
		}
		case ' ':
			last = arg.str();
			if(last.length() > 0) {
				argv.push_back(arg.str());
				if(argv.size() == maxargc) {
					return argv;
				}
			}
			arg.str(std::basic_string<T>());
			break;
		default:
		{
			std::wcmatch results;
			std::regex_search(&CmdLine[i], results, br);
			const auto & prefix = results[0];
			arg << converter.to_bytes(prefix);
			i += prefix.length() - 1;
			break;
		}
		}
		i++;
	}
	last = arg.str();
	if(last.length() > 0) {
		argv.push_back(arg.str());
	}
	return argv;
}

std::vector<std::string> _argv;

extern "C" NTSYSAPI NTSTATUS RtlGetVersion(
  PRTL_OSVERSIONINFOW lpVersionInformation
);

const char * charset;
UINT icodepage;
UINT codepage;
DWORD mode;

extern "C" const char * locale_charset() {
	return charset;
}

void msvc_exit()
{
	char ** &argv = __argv;
	if (argv)
	{
		HeapFree(GetProcessHeap(), 0, argv);
		argv = NULL;
	}
	SetConsoleCP(icodepage);
	SetConsoleOutputCP(codepage);
	SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), mode);
	WSACleanup();
}

// void msvc_startup()
// {
// 	{
// 		WSADATA data;
// 		WSAStartup(WINSOCK_VERSION, &data);
// 	}
// 	HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
// 	RTL_OSVERSIONINFOW ver;
// 	RtlGetVersion(&ver);
// 	icodepage = GetConsoleCP();
// 	codepage = GetConsoleOutputCP();
// 	GetConsoleMode(hout, &mode);
// 	if(ver.dwBuildNumber >= 14393) {
// 		charset = "utf-8";
// 		SetConsoleCP(CP_UTF8);
// 		SetConsoleOutputCP(CP_UTF8);
// 		setenv(u8"TERM", u8"xterm-256color", 0);
// 		SetConsoleMode(hout, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
// 	} else {
// 		char * chs = new char[10];
// 		chs[0] = 'c';
// 		chs[1] = 'p';
// 		itoa(codepage, chs + 2, 10);
// 		charset = chs;
// 	}
// 	setlocale( LC_ALL, ".65001" );
// 	_setmode(_fileno(stdin), _O_BINARY);
// 	_setmode(_fileno(stdout), _O_BINARY);
// 	_setmode(_fileno(stderr), _O_BINARY );
// 	_argv = CommandLineToArgv(GetCommandLineW());
// 	auto & argc = __argc = _argv.size();
// 	auto & argv = __argv = (char**)HeapAlloc(GetProcessHeap(), 0, (argc + 1) * sizeof(char*));
// 	for (int i = 0; i < argc; i++)
// 	{
// 		argv[i] = (char*)_argv[i].data();
// 	}
// 	argv[argc] = 0;
// 	atexit(msvc_exit);
// }

void SyncEnv()
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	for (auto& v : env)
	{
		std::wstring key = converter.from_bytes(v.first), value = converter.from_bytes(v.second);
		SetEnvironmentVariableW(key.data(), value.empty() ? NULL : value.data());
	}
}

struct process_t
{
	process_t()
	{
		process = NULL;
		envstr = NULL;
	}
	process_t(process_t && proc)
	{
		process = proc.process;
		proc.process = NULL;
		envstr = proc.envstr;
		proc.envstr = NULL;
		cmd = std::move(proc.cmd);
		dir = std::move(proc.dir);
		args = std::move(proc.args);
	}
	~process_t()
	{
		if (process)
			CloseHandle(process);
		if (envstr)
			FreeEnvironmentStringsW(envstr);
	}
	HANDLE process;
	wchar_t * envstr;
	std::wstring cmd;
	std::wstring args;
	std::wstring dir;
};

std::unordered_map<pid_t, process_t> process;

#undef spawnv
pid_t msvc_spawnve_fd(const char *cmd, char *const* argv, char ** deltaenv,	const char *dir, HANDLE hStdOutput, HANDLE hStdInput, HANDLE hStdError)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	BOOL ret;
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = hStdInput;
	si.hStdOutput = hStdOutput;
	si.hStdError = hStdError;
	process_t proc;
	std::wstring &wcmd = proc.cmd;
	std::wstring &wdir = proc.dir;
	std::wstring &args = proc.args;
	wchar_t * wenvblk;
	if (cmd != NULL)
	{
		wcmd = converter.from_bytes(cmd);
	}
	if (dir != NULL)
	{
		wdir = converter.from_bytes(dir);
	}
	bool syncenv = !env.empty();
	if(syncenv || deltaenv)
	{
		wchar_t* backup = GetEnvironmentStringsW();
		if(syncenv) {
			SyncEnv();
		}
		if(deltaenv) {
			while (*deltaenv) {
				std::wstring l = converter.from_bytes(*deltaenv++);
				wchar_t * eq = wcschr((wchar_t*)l.data(), L'=');
				if(eq) {
					*eq = 0;
					SetEnvironmentVariableW(l.data(), eq + 1);
				} else {
					SetEnvironmentVariableW(l.data(), nullptr);				
				}
			}
		}
		proc.envstr = wenvblk = GetEnvironmentStringsW();
		SetEnvironmentStringsW(backup);
		FreeEnvironmentStringsW(backup);
	}
	std::wstringstream wargs;
	wchar_t abspath[MAX_PATH];
	for(size_t i = 0; i < 2; i++)
	{
		if (SearchPathW(NULL, wcmd.data(), L".exe", MAX_PATH, abspath, NULL)) {
			wcmd = abspath;
		}
		else if (SearchPathW(NULL, wcmd.data(), L".cmd", MAX_PATH, abspath, NULL) || SearchPathW(NULL, wcmd.data(), L".bat", MAX_PATH, abspath, NULL))
		{
			wcmd = L"C:\\Windows\\system32\\cmd.exe";
			wargs << L"cmd /c ";
		} else if (SearchPathW(NULL, wcmd.data(), L".ps1", MAX_PATH, abspath, NULL))
		{
			wcmd = L"C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe";
			wargs << L"powershell -ExecutionPolicy RemoteSigned ";
		} else if(argv[0] && !argv[1]){
			wcmd = CommandLineToArgv<wchar_t, __noconv>(wcmd.data())[0];
			continue;
		}
		break;
	}
	std::wregex br = std::wregex(L"[^'\\\"\\s\t\n\r]+");
	std::wregex escape = std::wregex(L"(\\\\|\\\")");
	for (size_t i = 0; argv[i] != 0; i++)
	{
		if (i != 0)
			wargs << L' ';
		std::wstring arg = converter.from_bytes(argv[i]);
		bool quote = !std::regex_match(arg, br);
		if (quote)
			wargs << L'"';
		wargs << std::regex_replace(arg, escape, L"\\$1");
		if (quote)
			wargs << L'"';
	}
	args = wargs.str();
	ret = CreateProcessW(wcmd.data(), (LPWSTR)args.data(), NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT,
		wenvblk, wdir.empty() ? NULL : wdir.data(), &si, &pi);

	if (!ret) {
		errno = ENOENT;
		return -1;
	}
	CloseHandle(pi.hThread);
	pid_t pid = (pid_t)pi.dwProcessId;
	proc.process = pi.hProcess;
	process.insert({ pid, std::move(proc) });
	return pid;
}

pid_t msvc_spawnv(const char *cmd, char *const*argv)
{
	return msvc_spawnve_fd(cmd, argv, NULL, NULL, GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_ERROR_HANDLE));
}

#undef execv
int msvc_execv(const char *cmd, char * const *argv)
{
	pid_t pid = msvc_spawnv(cmd, argv);
	int status = -1;
	if (pid > 0) waitpid(pid, &status, 0);
	exit(status);
}

int msvc_execvp(const char *cmd, char *const *argv)
{
	if (cmd) {
		msvc_execv(cmd, argv);
	}
	else
		errno = ENOENT;
	return -1;
}

pid_t waitpid(pid_t pid, int *status, int options)
{
	if(pid > 0) {
		process_t & proc = process[pid];
		HANDLE& h = proc.process;
		if(!h) {
			h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, pid);
		}
		if (!h) {
			errno = ECHILD;
			return -1;
		}

		if (options & WNOHANG) {
			if (WaitForSingleObject(h, 0) != WAIT_OBJECT_0) {
				return 0;
			}
			options &= ~WNOHANG;
		}

		if (options == 0) {
			if (WaitForSingleObject(h, INFINITE) != WAIT_OBJECT_0) {
				return 0;
			}

			if (status) {
				GetExitCodeProcess(h, (LPDWORD)status);
			}

			process.erase(pid);
			return pid;
		}
	}

	errno = EINVAL;
	return -1;
}

#undef kill
int msvc_kill(pid_t pid, int sig)
{
	if(pid > 0) {
		process_t & proc = process[pid];
		HANDLE& h = proc.process;
		if (sig == SIGTERM) {
			if(!h) {
				h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
			}

			if(h) {
				if (TerminateProcess(h, -1)) {
					process.erase(pid);
					return 0;
				}
			}
			errno = err_win_to_posix(GetLastError());
			CloseHandle(h);
			return -1;
		}
		else if (sig == 0) {
			if(!h) {
				h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
			}
			if (h) {
				return 0;
			}
		}
	}

	errno = EINVAL;
	return -1;
}

#undef socket
int msvc_socket(int domain, int type, int protocol)
{
	int sockfd;
	SOCKET s;

	s = WSASocket(domain, type, protocol, NULL, 0, 0);
	if (s == INVALID_SOCKET) {
		/*
		* WSAGetLastError() values are regular BSD error codes
		* biased by WSABASEERR.
		* However, strerror() does not know about networking
		* specific errors, which are values beginning at 38 or so.
		* Therefore, we choose to leave the biased error code
		* in errno so that _if_ someone looks up the code somewhere,
		* then it is at least the number that are usually listed.
		*/
		errno = WSAGetLastError();
		return -1;
	}
	/* convert into a file descriptor */
	if ((sockfd = _open_osfhandle(s, O_RDWR | O_BINARY)) < 0) {
		closesocket(s);
		return -1;
	}
	return sockfd;
}

#undef connect
int msvc_connect(int sockfd, struct sockaddr *sa, size_t sz)
{
	SOCKET s = (SOCKET)_get_osfhandle(sockfd);
	return connect(s, sa, sz);
}

#undef bind
int msvc_bind(int sockfd, struct sockaddr *sa, size_t sz)
{
	SOCKET s = (SOCKET)_get_osfhandle(sockfd);
	return bind(s, sa, sz);
}

#undef setsockopt
int msvc_setsockopt(int sockfd, int lvl, int optname, void *optval, int optlen)
{
	SOCKET s = (SOCKET)_get_osfhandle(sockfd);
	return setsockopt(s, lvl, optname, (const char*)optval, optlen);
}

#undef shutdown
int msvc_shutdown(int sockfd, int how)
{
	SOCKET s = (SOCKET)_get_osfhandle(sockfd);
	return shutdown(s, how);
}

#undef listen
int msvc_listen(int sockfd, int backlog)
{
	SOCKET s = (SOCKET)_get_osfhandle(sockfd);
	return listen(s, backlog);
}

#undef accept
int msvc_accept(int sockfd1, struct sockaddr *sa, socklen_t *sz)
{
	int sockfd2;

	SOCKET s1 = (SOCKET)_get_osfhandle(sockfd1);
	SOCKET s2 = accept(s1, sa, sz);

	/* convert into a file descriptor */
	if ((sockfd2 = _open_osfhandle(s2, O_RDWR | O_BINARY)) < 0) {
		closesocket(s2);
		return -1;
	}
	return sockfd2;
}

#undef rename
int msvc_rename(const char *pold, const char *pnew)
{
	return !MoveFileExW(getPath(pold).data(), getPath(pnew).data(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

/*
* Note that this doesn't return the actual pagesize, but
* the allocation granularity. If future Windows specific git code
* needs the real getpagesize function, we need to find another solution.
*/
int getpagesize(void)
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return si.dwAllocationGranularity;
}

struct passwd *getpwuid(int uid)
{
	static char user_name[100];
	static struct passwd p;

	DWORD len = sizeof(user_name);
	if (!GetUserNameA(user_name, &len))
		return NULL;
	p.pw_name = user_name;
	p.pw_gecos = "unknown";
	p.pw_dir = NULL;
	return &p;
}

int symlink(const char * oldpath, const char * newpath)
{
	std::error_code code;
	auto poldpath = std::filesystem::u8path(oldpath);
	auto pnewpath = std::filesystem::u8path(newpath);
	if (std::filesystem::is_directory(poldpath))
	{
		std::filesystem::create_directory_symlink(poldpath, pnewpath, code);
	}
	else
	{
		std::filesystem::create_symlink(poldpath, pnewpath, code);
	}
	return code.value();
}

int readlink(const char *path, char *buf, size_t bufsiz)
{
	auto lnk = std::filesystem::u8path(path);
	if (std::filesystem::is_symlink(lnk))
	{
		return std::filesystem::read_symlink(lnk).u8string().copy(buf, bufsiz);
	}
	return -1;
}

int link(const char *oldpath, const char *newpath)
{
	std::error_code code;
	std::filesystem::create_hard_link(std::filesystem::u8path(oldpath), std::filesystem::u8path(newpath), code);
	return code.value();
}

// int uname(struct utsname *buf)
// {
// 	unsigned v = (unsigned)GetVersion();
// 	memset(buf, 0, sizeof(*buf));
// 	strcpy(buf->sysname, "Windows");
// 	snprintf(buf->release, sizeof(buf->release), "%u.%u", v & 0xff, (v >> 8) & 0xff);
// 	/* assuming NT variants only.. */
// 	snprintf(buf->version, sizeof(buf->version), "%u", (v >> 16) & 0x7fff);
// 	return 0;
// }

int fsync(int fd)
{
	return FlushFileBuffers((HANDLE)_get_osfhandle(fd)) ? 0 : -1;
}

std::unordered_map<int, struct sigaction> sig;
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	if (oldact && sig.find(signum) != sig.end())
	{
		auto & ac = sig[signum];
		oldact->sa_flags = ac.sa_flags;
		oldact->sa_handler = ac.sa_handler;
	}
	if (act)
	{
		auto & ac = sig[signum];
		ac.sa_flags = act->sa_flags;
		ac.sa_handler = act->sa_handler;
	}
	return 0;
}

#undef raise
int msvc_raise(int signum)
{
	if (sig.find(signum) != sig.end())
	{
		sig_handler_t h = sig[signum].sa_handler; 
		if (h == SIG_DFL)
			exit(128);
		if(h != SIG_IGN)
			h(signum);
		return 0;
	}
	return signum ? raise(signum) : 0;
}

#undef signal
sig_handler_t msvc_signal(int signum, sig_handler_t h)
{
	if (signum == SIGALRM || signum == SIGINT)
	{
		return sig[signum].sa_handler = h;
	}
	return signum == 0 ? 0 : signal(signum, h);
}


VOID CALLBACK WaitOrTimerCallback(
  _In_ PVOID   lpParameter,
  _In_ BOOLEAN TimerOrWaitFired
)
// void CALLBACK timer_raise(HWND , UINT, UINT_PTR,DWORD)
{
	msvc_raise(SIGALRM);
}

std::unordered_map<int, HANDLE> itimers;

int setitimer(int type, struct itimerval *in, struct itimerval *out)
{
	if (!in->it_interval.tv_sec && !in->it_interval.tv_usec)
	{
		if(!DeleteTimerQueueTimer(NULL, itimers[type], NULL)) {
			msvc_raise(SIGALRM);
		}
	}
	else
	{
		if(!CreateTimerQueueTimer(&itimers[type], NULL, &WaitOrTimerCallback, NULL, 10, in->it_interval.tv_sec * 1000 + in->it_interval.tv_usec / 1000, WT_EXECUTEINTIMERTHREAD)) {
			msvc_raise(SIGALRM);
		}
	}
	return 0;
}

extern "C" int xwcstoutf(char *utf, const wchar_t *wcs, size_t utflen)
{
	if (!wcs || !utf || utflen < 1) {
		errno = EINVAL;
		return -1;
	}
	utflen = WideCharToMultiByte(CP_UTF8, 0, wcs, -1, utf, utflen, NULL, NULL);
	if (utflen)
		return utflen - 1;
	errno = ERANGE;
	return -1;
}

#include <algorithm>

extern "C" char *strsep(char **stringp, const char *delim) {
	if(!stringp) return nullptr;
	auto ldel = strlen(delim);
	auto end = *stringp + strlen(*stringp);
	auto ret = std::search(*stringp, end, delim, delim + ldel);
	if(ret != end) {
		*ret = '\0';
		auto vret = *stringp;
		*stringp = ret + ldel;
		return vret;
	}
}
