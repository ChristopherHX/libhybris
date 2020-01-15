/*
 * Copyright (C) 2009 Andrzej K. Haczewski <ahaczewski@gmail.com>
 *
 * DISCLAIMER: The implementation is Git-specific, it is subset of original
 * Pthreads API, without lots of other features that Git doesn't use.
 * Git also makes sure that the passed arguments are valid, so there's
 * no need for double-checking.
 */

#include "pthread.h"

#include <errno.h>
#include <limits.h>

unsigned __stdcall win32_start_routine(void *arg)
{
	pthread_t thread = arg;
	thread->tid = GetCurrentThreadId();
	thread->arg = thread->start_routine(thread->arg);
	return 0;
}

int pthread_create(pthread_t *thread, const void *unused,
		   void *(*start_routine)(void*), void *arg)
{
	*thread = malloc(sizeof(**thread));
	(*thread)->arg = arg;
	(*thread)->start_routine = start_routine;
	(*thread)->handle = (HANDLE)
		_beginthreadex(NULL, 0, win32_start_routine, *thread, 0, NULL);

	if (!(*thread)->handle)
		return errno;
	else
		return 0;
}

int pthread_join(pthread_t thread, void **value_ptr)
{
	DWORD result = WaitForSingleObject(thread->handle, INFINITE);
	switch (result) {
		case WAIT_OBJECT_0:
			if (value_ptr)
				*value_ptr = thread->arg;
			return 0;
		case WAIT_ABANDONED:
			return EINVAL;
		default:
			return err_win_to_posix(GetLastError());
	}
}

pthread_t pthread_self(void)
{
	pthread_t t = malloc(sizeof(*t));
	t->tid = GetCurrentThreadId();
	return t;
}

int pthread_equal(pthread_t t1, pthread_t t2) {
	return ((t1)->tid == (t2)->tid);
}

void pthread_exit(void *ret)
{
	ExitThread((DWORD)(intptr_t)ret);
}

int pthread_kill(pthread_t thread, int sig) {
	HANDLE threadh = OpenThread(THREAD_TERMINATE, FALSE, thread->tid);
	TerminateThread(threadh, sig);
	CloseHandle(threadh);
	return 0;
}

int pthread_key_create(pthread_key_t *keyp, void (*destructor)(void *value))
{
	return (*keyp = TlsAlloc()) == TLS_OUT_OF_INDEXES ? EAGAIN : 0;
}

int pthread_key_delete(pthread_key_t key)
{
	return TlsFree(key) ? 0 : EINVAL;
}

int pthread_setspecific(pthread_key_t key, const void *value)
{
	return TlsSetValue(key, (void *)value) ? 0 : EINVAL;
}

void *pthread_getspecific(pthread_key_t key)
{
	return TlsGetValue(key);
}

#ifndef __MINGW64_VERSION_MAJOR
int pthread_sigmask(int how, const sigset_t *set, sigset_t *oset)
{
	return 0;
}
#endif

BOOL CALLBACK pthread_onceInternal(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *lpContex) {
    ((void (*)(void))Parameter)();
    return TRUE;
}

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

int pthread_mutexattr_getpshared(const pthread_mutexattr_t * attr, int * pshared) {
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
	if(thread && thread->handle != 0 && (void*)thread->handle != (void*)-1) {
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

int pthread_mutexattr_gettype(const pthread_mutexattr_t * attr, int * type) {
	return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type){
	return 0;
}

int pthread_attr_init(pthread_attr_t *attr) {
	return 0;
}
int pthread_attr_destroy(pthread_attr_t *attr) {
	return 0;
}
int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate) {
	return 0;
}
int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate) {
	return 0;
}
int pthread_attr_setschedparam(pthread_attr_t *attr, const struct sched_param *param) {
	return 0;
}
int pthread_attr_getschedparam(const pthread_attr_t *attr, struct sched_param *param) {
	return 0;
}
int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize) {
	return 0;
}
int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize) {
	return 0;
}
int pthread_attr_setstack(pthread_attr_t *attr,	void *stackaddr, size_t stacksize) {
	return 0;
}
int pthread_attr_getstack(const pthread_attr_t *attr, void **stackaddr, size_t *stacksize) {
	return 0;
}
int pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize) {
	return 0;
}
int pthread_attr_getguardsize(const pthread_attr_t *attr, size_t *guardsize) {
	return 0;
}
int pthread_attr_setscope(pthread_attr_t *attr, int scope) {
	return 0;
}
int pthread_attr_getscope(const pthread_attr_t *attr, int *scope) {
	return 0;
}