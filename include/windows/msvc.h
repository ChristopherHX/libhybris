#ifndef __MSVC__HEAD
#define __MSVC__HEAD

#pragma warning( disable : 4141)
typedef int sigset_t;
#include <sys/stat.h>
#include <sys/utime.h>
#include <direct.h>
#include <process.h>
#include <malloc.h>
#include <stdio.h>
#include <io.h>
#include <ws2tcpip.h>
#include <afunix.h>
#include <Shlwapi.h>
#include <Pathcch.h>
#include <signal.h>
#include <inttypes.h>

/* porting function */
#undef small
#ifndef __cplusplus
#define inline __inline
#define __inline__ __inline
#define __attribute__(x)
#define strcasecmp   _stricmp
#define strncasecmp  _strnicmp
#define ftruncate    _chsize
#define strtoull     _strtoui64
#define strtoll      _strtoi64
#define ftello		_ftelli64
#else
extern "C" {
#endif
#undef ERROR
	int lstat(const char * path, struct stat * const status);
	int msvc_unlink(const char *pathname);
#define unlink msvc_unlink
	int msvc_rmdir(const char *pathname);
#define rmdir msvc_rmdir
	int msvc_mkdir(const char *path, int mode);
#define mkdir msvc_mkdir
	int msvc_open(const char *filename, int oflags, ...);
#define open msvc_open
	int msvc_fgetc(FILE *stream);
#define fgetc msvc_fgetc
	FILE *msvc_fopen(const char *filename, const char *otype);
#define fopen msvc_fopen
	FILE *msvc_freopen(const char *filename, const char *otype, FILE *stream);
#define freopen msvc_freopen
	int msvc_access(const char *filename, int mode);
#define access msvc_access
	int msvc_chdir(const char *dirname);
#define chdir msvc_chdir
	int msvc_chmod(const char *filename, int mode);
#define chmod msvc_chmod
	int msvc_utime(const char *file_name, const struct utimbuf *times);
#define utime msvc_utime
	unsigned int sleep(unsigned int seconds);
	char *msvc_mktemp(char *templat);
#define mktemp msvc_mktemp
	int mkstemp(char *templat);
	int gettimeofday(struct timeval *tv, void *tz);
	struct tm *gmtime_r(const time_t *timep, struct tm *result);
	struct tm *localtime_r(const time_t *timep, struct tm *result);
	char *msvc_getcwd(char *pointer, int len);
#define getcwd msvc_getcwd
	const char *msvc_getenv(const char *_VarName);
#define getenv msvc_getenv
	int msvc_putenv(const char *_EnvString);
	typedef int pid_t;
	pid_t msvc_spawnv(const char *cmd, char *const*argv);
	pid_t msvc_spawnve_fd(const char *cmd, char *const* argv, char ** deltaenv, const char *dir, HANDLE hStdOutput, HANDLE hStdInput, HANDLE hStdError);
#define mingw_spawnvpe(cmd, argv, deltaenv, dir, fhin, fhout, fherr) msvc_spawnve_fd(cmd, argv, deltaenv, dir, fhout == 0 ? GetStdHandle(STD_OUTPUT_HANDLE) : _get_osfhandle(fhout), fhin == 1 ? GetStdHandle(STD_INPUT_HANDLE) : _get_osfhandle(fhin), fherr == 2 ? GetStdHandle(STD_ERROR_HANDLE) : _get_osfhandle(fherr))
#define spawnv msvc_spawnv
	int msvc_execv(const char *cmd, char *const *argv);
	int msvc_execvp(const char *cmd, char *const *argv);
#define execvp msvc_execvp
#define execv msvc_execv
	int msvc_kill(pid_t pid, int sig);
#define kill msvc_kill
	int msvc_socket(int domain, int type, int protocol);
#define socket msvc_socket
	int msvc_connect(int sockfd, struct sockaddr *sa, size_t sz);
#define connect msvc_connect
	int msvc_bind(int sockfd, struct sockaddr *sa, size_t sz);
#define bind msvc_bind
	int msvc_setsockopt(int sockfd, int lvl, int optname, void *optval, int optlen);
#define setsockopt msvc_setsockopt
	int msvc_shutdown(int sockfd, int how);
#define shutdown msvc_shutdown
	int msvc_listen(int sockfd, int backlog);
#define listen msvc_listen
	typedef int socklen_t;
	int msvc_accept(int sockfd1, struct sockaddr *sa, socklen_t *sz);
#define accept msvc_accept
	int msvc_rename(const char *pold, const char *pnew);
#define rename msvc_rename
	struct passwd *getpwuid(int uid);
	int symlink(const char * oldpath, const char * newpath);
	int readlink(const char *path, char *buf, size_t bufsiz);
	int link(const char *oldpath, const char *newpath);
	pid_t waitpid(pid_t pid, int *status, int options);
	void msvc_startup();
	struct utsname {
		char sysname[16];
		char nodename[1];
		char release[16];
		char version[16];
		char machine[1];
	};
	int uname(struct utsname *buf);
#define WNOHANG 1
	struct passwd {
		char *pw_name;
		char *pw_gecos;
		char *pw_dir;
	};
static inline unsigned int alarm(unsigned int seconds)
{ return 0; }
#define S_IFLNK    0120000 /* Symbolic link */
#define S_ISLNK(x) (((x) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(x) 0
#define SHUT_WR SD_SEND

#define SIGHUP 1
#define SIGQUIT 3
#define SIGKILL 9
#define SIGPIPE 13
#define SIGALRM 14
#define SIGCHLD 17
	struct itimerval {
		struct timeval it_value, it_interval;
	};

#define F_GETFD 1
#define F_SETFD 2
#define FD_CLOEXEC 0x1

#if !defined O_CLOEXEC && defined O_NOINHERIT
#define O_CLOEXEC	O_NOINHERIT
#endif

#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#endif
#ifndef ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#endif
#ifndef ENOTSOCK
#define ENOTSOCK WSAENOTSOCK
#endif

	static inline int fcntl(int fd, int cmd, ...)
	{
		if (cmd == F_GETFD || cmd == F_SETFD)
			return 0;
		errno = EINVAL;
		return -1;
	}

#define sigemptyset(x) (void)0
	static inline int sigaddset(sigset_t *set, int signum)
	{
		return 0;
	}
#define SIG_BLOCK 0
#define SIG_UNBLOCK 0
	static inline int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
	{
		return 0;
	}
	static inline pid_t getppid(void)
	{
		return 1;
	}
	static inline pid_t getpgid(pid_t pid)
	{
		return pid == 0 ? getpid() : pid;
	}
	static inline pid_t tcgetpgrp(int fd)
	{
		return getpid();
	}
	typedef void(__cdecl *sig_handler_t)(int);
	struct sigaction {
		sig_handler_t sa_handler;
		unsigned sa_flags;
	};

#ifndef S_IRWXG
#define S_IRGRP 0
#define S_IWGRP 0
#define S_IXGRP 0
#define S_IRWXG (S_IRGRP | S_IWGRP | S_IXGRP)
#endif
#ifndef S_IRWXO
#define S_IROTH 0
#define S_IWOTH 0
#define S_IXOTH 0
#define S_IRWXO (S_IROTH | S_IWOTH | S_IXOTH)
#endif

#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define WIFEXITED(x) 1
#define WIFSIGNALED(x) 0
#define WEXITSTATUS(x) ((x) & 0xff)
#define WTERMSIG(x) SIGTERM

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif
#ifndef ELOOP
#define ELOOP EMLINK
#endif

#define SA_RESTART 0

#define ITIMER_REAL 0

	static inline void convert_slashes(char *path)
	{
		for (; *path; path++)
			if (*path == '\\')
				*path = '/';
	}

	int getpagesize(void);
	int fsync(int fd);

	static inline struct passwd *getpwnam(const char *name)
	{
		return NULL;
	}

	typedef int uid_t;

	static inline uid_t getuid(void)
	{
		return 1;
	}
 
// #define pipe(fd) _pipe(fd, 128, O_BINARY | _O_NOINHERIT)
	int unsetenv(const char *name);
	int is_absolute_path(const char *path);
	int msvc_stat(const char * path, struct stat * status);
#define stat(a,b) msvc_stat(a,b)
	int setenv(const char *name, const char *value, int replace);
	int err_win_to_posix(DWORD winerr);
	const char * cwcstoutf8(wchar_t * in);
	int msvc_raise(int signum);
#define raise msvc_raise
	sig_handler_t msvc_signal(int signum, sig_handler_t h);
#define signal msvc_signal
	int setitimer(int type, struct itimerval *in, struct itimerval *out);
	int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
#define PATH_SEP ';'
#define DEFAULT_HELP_FORMAT "web"

#define MAP_PRIVATE (1<<0)
#define MAP_SHARED (1<<1)
#define MAP_ANONYMOUS (1<<2)
#define MAP_FIXED (1<<3)
#define MAP_FAILED ((void*)-1)
#define PROT_NONE 0
#define PROT_READ (1<<0)
#define PROT_WRITE (1<<1)
#define PROT_EXEC (1<<2)

void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset);

int munmap(void *start, size_t length);

int mprotect(void *addr, size_t len, int prot);
#ifdef __cplusplus
}
#endif
#endif