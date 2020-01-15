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

#ifdef __cplusplus
extern "C" {
#endif

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

extern pthread_t pthread_self(void);

int pthread_equal(pthread_t t1, pthread_t t2);

void pthread_exit(void *ret);
int pthread_kill(pthread_t thread, int sig);

typedef DWORD pthread_key_t;
int pthread_key_create(pthread_key_t *keyp, void (*destructor)(void *value));

int pthread_key_delete(pthread_key_t key);

int pthread_setspecific(pthread_key_t key, const void *value);

void *pthread_getspecific(pthread_key_t key);

#ifndef __MINGW64_VERSION_MAJOR
int pthread_sigmask(int how, const sigset_t *set, sigset_t *oset);
#endif

typedef volatile int pthread_once_t;
int pthread_once(pthread_once_t  *once_control, void (*init_routine)(void));

int pthread_setname_np(pthread_t thid, const char *thname);
int pthread_mutexattr_getpshared(const pthread_mutexattr_t * attr, int * pshared);
int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr,	int pshared);

int pthread_condattr_getpshared(pthread_condattr_t *attr, int *pshared);
int pthread_condattr_setpshared(pthread_condattr_t* attr, int pshared);

int pthread_detach(pthread_t thread);
struct sched_param {};
int pthread_setschedparam(pthread_t thread, int policy, const struct sched_param *param);
int pthread_getschedparam(pthread_t thread, int *policy, struct sched_param *param);

int pthread_mutexattr_init(pthread_mutexattr_t *attr);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);

int pthread_condattr_init(pthread_condattr_t *attr);

int pthread_condattr_destroy(pthread_condattr_t *attr);

int pthread_mutexattr_gettype(const pthread_mutexattr_t * attr, int * type);

int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);

int pthread_mutex_timedlock(pthread_mutex_t * mutex, const struct timespec * abstime);

// int pthread_cond_timedwait(pthread_cond_t * cond, pthread_mutex_t * mutex, const struct timespec * abstime);
#define pthread_cond_timedwait(a,b,c) return_0((SleepConditionVariableCS((a), (b), abstime->tv_sec * 1000 + abstime->tv_nsec / 1000000),0))

int pthread_attr_init(pthread_attr_t *attr);
int pthread_attr_destroy(pthread_attr_t *attr);
int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate);
int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate);
int pthread_attr_setschedparam(pthread_attr_t *attr, const struct sched_param *param);
int pthread_attr_getschedparam(const pthread_attr_t *attr, struct sched_param *param);
int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize);
int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize);
int pthread_attr_setstack(pthread_attr_t *attr,	void *stackaddr, size_t stacksize);
int pthread_attr_getstack(const pthread_attr_t *attr, void **stackaddr, size_t *stacksize);
int pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize);
int pthread_attr_getguardsize(const pthread_attr_t *attr, size_t *guardsize);
int pthread_attr_setscope(pthread_attr_t *attr, int scope);
int pthread_attr_getscope(const pthread_attr_t *attr, int *scope);
#ifdef __cplusplus
}
#endif

#endif /* PTHREAD_H */
