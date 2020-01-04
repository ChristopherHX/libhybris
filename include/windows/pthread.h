/*
 * Header used to adapt pthread-based POSIX code to Windows API threads.
 *
 * Copyright (C) 2009 Andrzej K. Haczewski <ahaczewski@gmail.com>
 */

#ifndef PTHREAD_H
#define PTHREAD_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "msvc.h"

/*
 * Defines that adapt Windows API threads to pthreads API
 */
#define pthread_mutex_t CRITICAL_SECTION

static int return_0(int i) {
	return 0;
}
#define pthread_mutex_init(a,b) return_0((InitializeCriticalSection((a)), 0))
#define pthread_mutex_destroy(a) return_0((DeleteCriticalSection((a)),0))
#define pthread_mutex_lock(a) return_0((EnterCriticalSection((a)),0))
#define pthread_mutex_trylock !TryEnterCriticalSection
#define pthread_mutex_unlock(a) return_0((LeaveCriticalSection((a)),0))
#define PTHREAD_PROCESS_PRIVATE 0
#define PTHREAD_PROCESS_SHARED 0
#define CLOCK_REALTIME 0

typedef int pthread_mutexattr_t;
typedef int pthread_condattr_t;
typedef int pthread_attr_t;
typedef int pthread_rwlockattr_t;
typedef int pthread_rwlock_t;
#define PTHREAD_MUTEX_RECURSIVE 0

#define pthread_cond_t CONDITION_VARIABLE

#define pthread_cond_init(a,b) return_0((InitializeConditionVariable((a)),0))
#define pthread_cond_destroy(a) return_0(0)
#define pthread_cond_wait(a,b) return_0((SleepConditionVariableCS((a), (b), INFINITE),0))
#define pthread_cond_signal(a) return_0((WakeConditionVariable((a)),0))
#define pthread_cond_broadcast(a) return_0((WakeAllConditionVariable((a)),0))

/*
 * Simple thread creation implementation using pthread API
 */
typedef struct {
	HANDLE handle;
	void *(*start_routine)(void*);
	void *arg;
	DWORD tid;
} *pthread_t;

extern int pthread_create(pthread_t *thread, const void *unused,
			  void *(*start_routine)(void*), void *arg);

/*
 * To avoid the need of copying a struct, we use small macro wrapper to pass
 * pointer to win32_pthread_join instead.
 */

extern int pthread_join(pthread_t thread, void **value_ptr);

int pthread_equal(pthread_t t1, pthread_t t2) {
	return ((t1)->tid == (t2)->tid);
}
extern pthread_t pthread_self(void);

static void pthread_exit(void *ret)
{
	ExitThread((DWORD)(intptr_t)ret);
}

int pthread_kill(pthread_t thread, int sig) {
	HANDLE threadh = OpenThread(THREAD_TERMINATE, FALSE, thread->tid);
	TerminateThread(threadh, sig);
	CloseHandle(threadh);
	return 0;
}

typedef DWORD pthread_key_t;
static int pthread_key_create(pthread_key_t *keyp, void (*destructor)(void *value))
{
	return (*keyp = TlsAlloc()) == TLS_OUT_OF_INDEXES ? EAGAIN : 0;
}

static int pthread_key_delete(pthread_key_t key)
{
	return TlsFree(key) ? 0 : EINVAL;
}

static int pthread_setspecific(pthread_key_t key, const void *value)
{
	return TlsSetValue(key, (void *)value) ? 0 : EINVAL;
}

static void *pthread_getspecific(pthread_key_t key)
{
	return TlsGetValue(key);
}

#ifndef __MINGW64_VERSION_MAJOR
static int pthread_sigmask(int how, const sigset_t *set, sigset_t *oset)
{
	return 0;
}
#endif

BOOL CALLBACK pthread_onceInternal(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *lpContex) {
    ((void (*)(void))Parameter)();
    return TRUE;
}

typedef volatile int pthread_once_t;
int pthread_once(pthread_once_t  *once_control, void (*init_routine)(void)) {
    InitOnceExecuteOnce((PINIT_ONCE) once_control, pthread_onceInternal, init_routine, NULL);
	return 0;
}

//  
// Usage: SetThreadName ((DWORD)-1, "MainThread");  
//  
#include <windows.h>  
const DWORD MS_VC_EXCEPTION = 0x406D1388;  
#pragma pack(push,8)  
typedef struct tagTHREADNAME_INFO  
{  
    DWORD dwType; // Must be 0x1000.  
    LPCSTR szName; // Pointer to name (in user addr space).  
    DWORD dwThreadID; // Thread ID (-1=caller thread).  
    DWORD dwFlags; // Reserved for future use, must be zero.  
 } THREADNAME_INFO;  
#pragma pack(pop)  
void SetThreadName(DWORD dwThreadID, const char* threadName) {  
    THREADNAME_INFO info;  
    info.dwType = 0x1000;  
    info.szName = threadName;  
    info.dwThreadID = dwThreadID;  
    info.dwFlags = 0;  
#pragma warning(push)  
#pragma warning(disable: 6320 6322)  
    __try{  
        RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);  
    }  
    __except (EXCEPTION_EXECUTE_HANDLER){  
    }  
#pragma warning(pop)  
}  
  

int pthread_setname_np(pthread_t thid, const char *thname) {
	SetThreadName(thid->tid, thname);
	return 0;
}

int pthread_mutexattr_getpshared(const pthread_mutexattr_t *restrict attr, int *restrict pshared) {
	return 0;
}
int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr,	int pshared) {
	return 0;
}

int pthread_condattr_getpshared(pthread_condattr_t *attr, int *pshared) {
	*pshared = 0;
	return 0;
}

int pthread_condattr_setpshared(pthread_condattr_t* attr, int pshared) {
	return 0;
}

int pthread_detach(pthread_t thread) {
	if(thread && thread->handle != 0 && thread->handle != -1) {
		CloseHandle(thread->handle);
	}
}

int pthread_setschedparam(pthread_t thread, int policy, const struct sched_param *param) {
	return 0;
}
int pthread_getschedparam(pthread_t thread, int *policy, struct sched_param *param) {
	return 0;
}

int pthread_mutexattr_init(pthread_mutexattr_t *attr) {
	return 0;
}
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr) {
	return 0;
}

int pthread_condattr_init(pthread_condattr_t *attr){
	return 0;
}

int pthread_condattr_destroy(pthread_condattr_t *attr) {
	return 0;
}

int pthread_mutexattr_gettype(const pthread_mutexattr_t *restrict attr, int *restrict type) {
	return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type){
	return 0;
}

#define PTHREAD_MUTEX_INITIALIZER {}

#endif /* PTHREAD_H */
