#ifdef _WIN32
#include <windows/pthread.h>
#include <windows/semaphore.h>
#else
#include <pthread.h>
#include <semaphore.h>
#endif
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#ifdef __APPLE__
#include <mach/mach_init.h>
#include <mach/task.h>
#include <mach/semaphore.h>
#include "hooks_darwin_pthread_once.h"
#elif !defined(_WIN32)
#include <sys/syscall.h>
#include <sys/auxv.h>
#endif
#include "../include/hybris/hook.h"
#include "hooks_shm.h"

#include "logging.h"
#define LOGD(message, ...) HYBRIS_DEBUG_LOG(HOOKS, message, ##__VA_ARGS__)

/* TODO:
*  - Check if the int arguments at attr_set/get match the ones at Android
*  - Check how to deal with memory leaks (specially with static initializers)
*  - Check for shared rwlock
*/

/* Base address to check for Android specifics */
#define ANDROID_TOP_ADDR_VALUE_MUTEX  0xFFFF
#define ANDROID_TOP_ADDR_VALUE_COND   0xFFFF
#define ANDROID_TOP_ADDR_VALUE_RWLOCK 0xFFFF

#define ANDROID_MUTEX_SHARED_MASK      0x2000
#define ANDROID_COND_SHARED_MASK       0x0001
#define ANDROID_RWLOCKATTR_SHARED_MASK 0x0010

/* For the static initializer types */
#define ANDROID_PTHREAD_MUTEX_INITIALIZER            0
#define ANDROID_PTHREAD_RECURSIVE_MUTEX_INITIALIZER  0x4000
#define ANDROID_PTHREAD_ERRORCHECK_MUTEX_INITIALIZER 0x8000
#define ANDROID_PTHREAD_COND_INITIALIZER             0
#define ANDROID_PTHREAD_RWLOCK_INITIALIZER           0

pthread_mutex_t hybris_static_init_mutex;// = PTHREAD_MUTEX_INITIALIZER;

/* Helpers */
static int hybris_check_android_shared_mutex(unsigned int mutex_addr)
{
    /* If not initialized or initialized by Android, it should contain a low
     * address, which is basically just the int values for Android's own
     * pthread_mutex_t */
    if ((mutex_addr <= ANDROID_TOP_ADDR_VALUE_MUTEX) &&
        (mutex_addr & ANDROID_MUTEX_SHARED_MASK))
        return 1;

    return 0;
}

static int hybris_check_android_shared_cond(unsigned int cond_addr)
{
    /* If not initialized or initialized by Android, it should contain a low
     * address, which is basically just the int values for Android's own
     * pthread_cond_t */
    if ((cond_addr <= ANDROID_TOP_ADDR_VALUE_COND) &&
        (cond_addr & ANDROID_COND_SHARED_MASK))
        return 1;

    return 0;
}

static void hybris_set_mutex_attr(unsigned int android_value, pthread_mutexattr_t *attr)
{
    /* Init already sets as PTHREAD_MUTEX_NORMAL */
    pthread_mutexattr_init(attr);

    if (android_value & ANDROID_PTHREAD_RECURSIVE_MUTEX_INITIALIZER) {
        pthread_mutexattr_settype(attr, PTHREAD_MUTEX_RECURSIVE);
    }
#ifndef _WIN32
else if (android_value & ANDROID_PTHREAD_ERRORCHECK_MUTEX_INITIALIZER) {
        pthread_mutexattr_settype(attr, PTHREAD_MUTEX_ERRORCHECK);
    }
#endif
}

static pthread_mutex_t* hybris_alloc_init_mutex(unsigned int android_mutex)
{
    pthread_mutex_t *realmutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutexattr_t attr;
    hybris_set_mutex_attr(android_mutex, &attr);
    pthread_mutex_init(realmutex, &attr);
    return realmutex;
}

static pthread_cond_t* hybris_alloc_init_cond(void)
{
    pthread_cond_t *realcond = malloc(sizeof(pthread_cond_t));
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_cond_init(realcond, &attr);
    return realcond;
}

static pthread_rwlock_t* hybris_alloc_init_rwlock(void)
{
    pthread_rwlock_t *realrwlock = malloc(sizeof(pthread_rwlock_t));
    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
    pthread_rwlock_init(realrwlock, &attr);
    return realrwlock;
}

/*
 * Main pthread functions
 *
 * Custom implementations to workaround difference between Bionic and Glibc.
 * Our own pthread_create helps avoiding direct handling of TLS.
 *
 * */

static int my_pthread_create(pthread_t *thread, const pthread_attr_t *__attr,
                             void *(*start_routine)(void*), void *arg)
{
    pthread_attr_t *realattr = NULL;

    if (__attr != NULL)
        realattr = (pthread_attr_t *) *(unsigned int *) __attr;

    return pthread_create(thread, realattr, start_routine, arg);
}

/*
 * pthread_attr_* functions
 *
 * Specific implementations to workaround the differences between at the
 * pthread_attr_t struct differences between Bionic and Glibc.
 *
 * */

static int my_pthread_attr_init(pthread_attr_t *__attr)
{
    pthread_attr_t *realattr;

    realattr = malloc(sizeof(pthread_attr_t));
    *((unsigned int *)__attr) = (unsigned int) realattr;

    return pthread_attr_init(realattr);
}

static int my_pthread_attr_destroy(pthread_attr_t *__attr)
{
    int ret;
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;

    ret = pthread_attr_destroy(realattr);
    /* We need to release the memory allocated at my_pthread_attr_init
     * Possible side effects if destroy is called without our init */
    free(realattr);

    return ret;
}

static int my_pthread_attr_setdetachstate(pthread_attr_t *__attr, int state)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_setdetachstate(realattr, state);
}

static int my_pthread_attr_getdetachstate(pthread_attr_t const *__attr, int *state)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_getdetachstate(realattr, state);
}

static int my_pthread_attr_setschedpolicy(pthread_attr_t *__attr, int policy)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_setschedpolicy(realattr, policy);
}

static int my_pthread_attr_getschedpolicy(pthread_attr_t const *__attr, int *policy)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_getschedpolicy(realattr, policy);
}

#ifndef __APPLE__
static int my_pthread_attr_setschedparam(pthread_attr_t *__attr, struct sched_param const *param)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_setschedparam(realattr, param);
}

static int my_pthread_attr_getschedparam(pthread_attr_t const *__attr, struct sched_param *param)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_getschedparam(realattr, param);
}
#endif

static int my_pthread_attr_setstacksize(pthread_attr_t *__attr, size_t stack_size)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_setstacksize(realattr, stack_size);
}

static int my_pthread_attr_getstacksize(pthread_attr_t const *__attr, size_t *stack_size)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_getstacksize(realattr, stack_size);
}

static int my_pthread_attr_setstack(pthread_attr_t *__attr, void *stack_base, size_t stack_size)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_setstack(realattr, stack_base, stack_size);
}

static int my_pthread_attr_getstack(pthread_attr_t const *__attr, void **stack_base, size_t *stack_size)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_getstack(realattr, stack_base, stack_size);
}

static int my_pthread_attr_setguardsize(pthread_attr_t *__attr, size_t guard_size)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_setguardsize(realattr, guard_size);
}

static int my_pthread_attr_getguardsize(pthread_attr_t const *__attr, size_t *guard_size)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_getguardsize(realattr, guard_size);
}

static int my_pthread_attr_setscope(pthread_attr_t *__attr, int scope)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    return pthread_attr_setscope(realattr, scope);
}

static int my_pthread_attr_getscope(pthread_attr_t const *__attr)
{
    int scope;
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;

    /* Android doesn't have the scope attribute because it always
     * returns PTHREAD_SCOPE_SYSTEM */
    pthread_attr_getscope(realattr, &scope);

    return scope;
}

#ifndef __APPLE__
static int my_pthread_getattr_np(pthread_t thid, pthread_attr_t *__attr)
{
    pthread_attr_t *realattr;

    realattr = malloc(sizeof(pthread_attr_t));
    *((unsigned int *)__attr) = (unsigned int) realattr;

    return pthread_getattr_np(thid, realattr);
}
#endif

/*
 * pthread_mutex* functions
 *
 * Specific implementations to workaround the differences between at the
 * pthread_mutex_t struct differences between Bionic and Glibc.
 *
 * */

#ifdef __APPLE__
static pthread_mutexattr_t *hybris_get_real_mutexattr(__const pthread_mutexattr_t *attr) {
    if (!attr)
        return NULL;
    pthread_mutexattr_t *realattr = (pthread_mutexattr_t *) *(unsigned int *) attr;
    return realattr;
}
#endif

static int my_pthread_mutex_init(pthread_mutex_t *__mutex,
                                 __const pthread_mutexattr_t *__mutexattr)
{
    pthread_mutex_t *realmutex = NULL;

#ifdef __APPLE__
    __mutexattr = hybris_get_real_mutexattr(__mutexattr);
#endif

    int pshared = PTHREAD_PROCESS_PRIVATE;
    if (__mutexattr)
        pthread_mutexattr_getpshared(__mutexattr, &pshared);

    if (pshared == PTHREAD_PROCESS_PRIVATE) {
        /* non shared, standard mutex: use malloc */
        realmutex = malloc(sizeof(pthread_mutex_t));

        *((unsigned int *)__mutex) = (unsigned int) realmutex;
    }
    else {
        /* process-shared mutex: use the shared memory segment */
        hybris_shm_pointer_t handle = hybris_shm_alloc(sizeof(pthread_mutex_t));

        *((hybris_shm_pointer_t *)__mutex) = handle;

        if (handle)
            realmutex = (pthread_mutex_t *)hybris_get_shmpointer(handle);
    }

    return pthread_mutex_init(realmutex, __mutexattr);
}

static int my_pthread_mutex_destroy(pthread_mutex_t *__mutex)
{
    int ret;

    if (!__mutex)
        return EINVAL;

    pthread_mutex_t *realmutex = (pthread_mutex_t *) *(unsigned int *) __mutex;

    if (!realmutex)
        return EINVAL;

    if (!hybris_is_pointer_in_shm((void*)realmutex)) {
        ret = pthread_mutex_destroy(realmutex);
        free(realmutex);
    }
    else {
        realmutex = (pthread_mutex_t *)hybris_get_shmpointer((hybris_shm_pointer_t)realmutex);
        ret = pthread_mutex_destroy(realmutex);
    }

    *((unsigned int *)__mutex) = 0;

    return ret;
}

static pthread_mutex_t *my_static_init_mutex(pthread_mutex_t *__mutex) {
    pthread_mutex_lock(&hybris_static_init_mutex);
    unsigned int value = (*(unsigned int *) __mutex);
    pthread_mutex_t *realmutex = (pthread_mutex_t *) value;
    if (value <= ANDROID_TOP_ADDR_VALUE_MUTEX) {
        realmutex = hybris_alloc_init_mutex(value);
        *((unsigned int*) __mutex) = (unsigned int) realmutex;
    }
    pthread_mutex_unlock(&hybris_static_init_mutex);
    return realmutex;
}


static pthread_cond_t *my_static_init_cond(pthread_cond_t *__cond) {
    pthread_mutex_lock(&hybris_static_init_mutex);
    unsigned int value = (*(unsigned int *) __cond);
    pthread_cond_t *realcond = (pthread_cond_t *) value;
    if (value <= ANDROID_TOP_ADDR_VALUE_MUTEX) {
        realcond = hybris_alloc_init_cond();
        *((unsigned int*) __cond) = (unsigned int) realcond;
    }
    pthread_mutex_unlock(&hybris_static_init_mutex);
    return realcond;
}

static int my_pthread_mutex_lock(pthread_mutex_t *__mutex)
{
    if (!__mutex) {
        LOGD("Null mutex lock, not locking.");
        return 0;
    }

    unsigned int value = (*(unsigned int *) __mutex);
    if (hybris_check_android_shared_mutex(value)) {
        LOGD("Shared mutex with Android, not locking.");
        return 0;
    }

    pthread_mutex_t *realmutex = (pthread_mutex_t *) value;
    if (hybris_is_pointer_in_shm((void*)value))
        realmutex = (pthread_mutex_t *)hybris_get_shmpointer((hybris_shm_pointer_t)value);

    if (value <= ANDROID_TOP_ADDR_VALUE_MUTEX) {
        realmutex = my_static_init_mutex(__mutex);
    }

    return pthread_mutex_lock(realmutex);
}

static int my_pthread_mutex_trylock(pthread_mutex_t *__mutex)
{
    unsigned int value = (*(unsigned int *) __mutex);

    if (hybris_check_android_shared_mutex(value)) {
        LOGD("Shared mutex with Android, not try locking.");
        return 0;
    }

    pthread_mutex_t *realmutex = (pthread_mutex_t *) value;
    if (hybris_is_pointer_in_shm((void*)value))
        realmutex = (pthread_mutex_t *)hybris_get_shmpointer((hybris_shm_pointer_t)value);

    if (value <= ANDROID_TOP_ADDR_VALUE_MUTEX) {
        realmutex = my_static_init_mutex(__mutex);
    }

    return pthread_mutex_trylock(realmutex);
}

static int my_pthread_mutex_unlock(pthread_mutex_t *__mutex)
{
    if (!__mutex) {
        LOGD("Null mutex lock, not unlocking.");
        return 0;
    }

    unsigned int value = (*(unsigned int *) __mutex);
    if (hybris_check_android_shared_mutex(value)) {
        LOGD("Shared mutex with Android, not unlocking.");
        return 0;
    }

    if (value <= ANDROID_TOP_ADDR_VALUE_MUTEX) {
        LOGD("Trying to unlock a lock that's not locked/initialized"
                     " by Hybris, not unlocking.");
        return 0;
    }

    pthread_mutex_t *realmutex = (pthread_mutex_t *) value;
    if (hybris_is_pointer_in_shm((void*)value))
        realmutex = (pthread_mutex_t *)hybris_get_shmpointer((hybris_shm_pointer_t)value);

    return pthread_mutex_unlock(realmutex);
}

/*
 * pthread_cond* functions
 *
 * Specific implementations to workaround the differences between at the
 * pthread_cond_t struct differences between Bionic and Glibc.
 *
 * */

static int my_pthread_cond_init(pthread_cond_t *cond,
                                const pthread_condattr_t *attr)
{
    pthread_cond_t *realcond = NULL;

    int pshared = PTHREAD_PROCESS_PRIVATE;

    if (attr)
        pthread_condattr_getpshared(attr, &pshared);

    if (pshared == PTHREAD_PROCESS_PRIVATE) {
        /* non shared, standard cond: use malloc */
        realcond = malloc(sizeof(pthread_cond_t));

        *((unsigned int *) cond) = (unsigned int) realcond;
    }
    else {
        /* process-shared condition: use the shared memory segment */
        hybris_shm_pointer_t handle = hybris_shm_alloc(sizeof(pthread_cond_t));

        *((unsigned int *)cond) = (unsigned int) handle;

        if (handle)
            realcond = (pthread_cond_t *)hybris_get_shmpointer(handle);
    }

    return pthread_cond_init(realcond, attr);
}

static int my_pthread_cond_destroy(pthread_cond_t *cond)
{
    int ret;
    pthread_cond_t *realcond = (pthread_cond_t *) *(unsigned int *) cond;

    if (!realcond) {
        return EINVAL;
    }

    if (!hybris_is_pointer_in_shm((void*)realcond)) {
        ret = pthread_cond_destroy(realcond);
        free(realcond);
    }
    else {
        realcond = (pthread_cond_t *)hybris_get_shmpointer((hybris_shm_pointer_t)realcond);
        ret = pthread_cond_destroy(realcond);
    }

    *((unsigned int *)cond) = 0;

    return ret;
}

static int my_pthread_cond_broadcast(pthread_cond_t *cond)
{
    unsigned int value = (*(unsigned int *) cond);
    if (hybris_check_android_shared_cond(value)) {
        LOGD("shared condition with Android, not broadcasting.");
        return 0;
    }

    pthread_cond_t *realcond = (pthread_cond_t *) value;
    if (hybris_is_pointer_in_shm((void*)value))
        realcond = (pthread_cond_t *)hybris_get_shmpointer((hybris_shm_pointer_t)value);

    if (value <= ANDROID_TOP_ADDR_VALUE_COND) {
        realcond = hybris_alloc_init_cond();
        *((unsigned int *) cond) = (unsigned int) realcond;
    }

    return pthread_cond_broadcast(realcond);
}

static int my_pthread_cond_signal(pthread_cond_t *cond)
{
    unsigned int value = (*(unsigned int *) cond);

    if (hybris_check_android_shared_cond(value)) {
        LOGD("Shared condition with Android, not signaling.");
        return 0;
    }

    pthread_cond_t *realcond = (pthread_cond_t *) value;
    if (hybris_is_pointer_in_shm((void*)value))
        realcond = (pthread_cond_t *)hybris_get_shmpointer((hybris_shm_pointer_t)value);

    if (value <= ANDROID_TOP_ADDR_VALUE_COND) {
        realcond = hybris_alloc_init_cond();
        *((unsigned int *) cond) = (unsigned int) realcond;
    }

    return pthread_cond_signal(realcond);
}

static int my_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    /* Both cond and mutex can be statically initialized, check for both */
    unsigned int cvalue = (*(unsigned int *) cond);
    unsigned int mvalue = (*(unsigned int *) mutex);

    if (hybris_check_android_shared_cond(cvalue) ||
        hybris_check_android_shared_mutex(mvalue)) {
        LOGD("Shared condition/mutex with Android, not waiting.");
        return 0;
    }

    pthread_cond_t *realcond = (pthread_cond_t *) cvalue;
    if (hybris_is_pointer_in_shm((void*)cvalue))
        realcond = (pthread_cond_t *)hybris_get_shmpointer((hybris_shm_pointer_t)cvalue);

    if (cvalue <= ANDROID_TOP_ADDR_VALUE_COND) {
        realcond = my_static_init_cond(cond);
    }

    pthread_mutex_t *realmutex = (pthread_mutex_t *) mvalue;
    if (hybris_is_pointer_in_shm((void*)mvalue))
        realmutex = (pthread_mutex_t *)hybris_get_shmpointer((hybris_shm_pointer_t)mvalue);

    if (mvalue <= ANDROID_TOP_ADDR_VALUE_MUTEX) {
        realmutex = my_static_init_mutex(mutex);
    }

    return pthread_cond_wait(realcond, realmutex);
}

static int my_pthread_cond_timedwait(pthread_cond_t *cond,
                                     pthread_mutex_t *mutex, const struct timespec *abstime)
{
    /* Both cond and mutex can be statically initialized, check for both */
    unsigned int cvalue = (*(unsigned int *) cond);
    unsigned int mvalue = (*(unsigned int *) mutex);

    if (hybris_check_android_shared_cond(cvalue) ||
        hybris_check_android_shared_mutex(mvalue)) {
        LOGD("Shared condition/mutex with Android, not waiting.");
        return 0;
    }

    pthread_cond_t *realcond = (pthread_cond_t *) cvalue;
    if (hybris_is_pointer_in_shm((void*)cvalue))
        realcond = (pthread_cond_t *)hybris_get_shmpointer((hybris_shm_pointer_t)cvalue);

    if (cvalue <= ANDROID_TOP_ADDR_VALUE_COND) {
        realcond = my_static_init_cond(cond);
    }

    pthread_mutex_t *realmutex = (pthread_mutex_t *) mvalue;
    if (hybris_is_pointer_in_shm((void*)mvalue))
        realmutex = (pthread_mutex_t *)hybris_get_shmpointer((hybris_shm_pointer_t)mvalue);

    if (mvalue <= ANDROID_TOP_ADDR_VALUE_MUTEX) {
        realmutex = my_static_init_mutex(mutex);
    }

    return pthread_cond_timedwait(realcond, realmutex, abstime);
}

static pthread_rwlock_t* hybris_set_realrwlock(pthread_rwlock_t *rwlock)
{
    unsigned int value = (*(unsigned int *) rwlock);
    pthread_rwlock_t *realrwlock = (pthread_rwlock_t *) value;
    if (hybris_is_pointer_in_shm((void*)value))
        realrwlock = (pthread_rwlock_t *)hybris_get_shmpointer((hybris_shm_pointer_t)value);

    if ((unsigned int)realrwlock <= ANDROID_TOP_ADDR_VALUE_RWLOCK) {
        realrwlock = hybris_alloc_init_rwlock();
        *((unsigned int *)rwlock) = (unsigned int) realrwlock;
    }
    return realrwlock;
}

static void my_pthread_cleanup_push(void (*routine)(void *),
                                    void *arg)
{
    LOGD("pthread_cleanup_push: not implemented");
}

static void my_pthread_cleanup_pop(int execute)
{
    LOGD("pthread_cleanup_pop: not implemented");
}


static pid_t my_gettid( void )
{
#ifdef __APPLE__
    return (pid_t) (void*) pthread_self();
#elif _WIN32
    return (pid_t)GetCurrentThreadId();
#else
    return syscall( __NR_gettid );
#endif
}

#ifdef __APPLE__

static int darwin_my_pthread_mutexattr_init(pthread_mutexattr_t *__attr)
{
    pthread_mutexattr_t *attr = malloc(sizeof(pthread_mutexattr_t));
    *((unsigned int *) __attr) = (unsigned int) attr;
    return pthread_mutexattr_init(attr);
}

static int darwin_my_pthread_mutexattr_destroy(pthread_mutexattr_t *__attr)
{
    pthread_mutexattr_t *attr = hybris_get_real_mutexattr(__attr);
    int ret = pthread_mutexattr_destroy(attr);
    free(attr);
    return ret;
}

static int darwin_my_pthread_mutexattr_gettype(pthread_mutexattr_t *__attr,
                                               int *__kind)
{
    return pthread_mutexattr_gettype(hybris_get_real_mutexattr(__attr), __kind);
}

static int darwin_my_pthread_mutexattr_settype(pthread_mutexattr_t *__attr,
                                               int __kind)
{
    return pthread_mutexattr_settype(hybris_get_real_mutexattr(__attr), __kind);
}

static int darwin_my_pthread_mutexattr_getpshared(pthread_mutexattr_t *__attr,
                                                  int *pshared)
{
    int ret = pthread_mutexattr_getpshared(hybris_get_real_mutexattr(__attr), pshared);
    if (*pshared == PTHREAD_PROCESS_PRIVATE)
        *pshared = 0;
    else if (*pshared == PTHREAD_PROCESS_SHARED)
        *pshared = 1;
    return ret;
}

static int darwin_my_pthread_mutexattr_setpshared(pthread_mutexattr_t *__attr,
                                                  int pshared)
{
    pshared = pshared == 1 ? PTHREAD_PROCESS_SHARED : PTHREAD_PROCESS_PRIVATE;
    return pthread_mutexattr_setpshared(__attr, pshared);
}


struct bionic_sched_param {
    int sched_priority;
};

static int darwin_my_pthread_getschedparam(pthread_t thread, int *policy, struct bionic_sched_param *param)
{
    struct sched_param realparam;
    int ret = pthread_getschedparam(thread, policy, &realparam);
    if (param != NULL)
      param->sched_priority = realparam.sched_priority;
    return ret;
}

static int darwin_my_pthread_setschedparam(pthread_t thread, int policy, struct bionic_sched_param *param)
{
    struct sched_param realparam;
    pthread_getschedparam(thread, NULL, &realparam);
    realparam.sched_priority = param->sched_priority;
    return pthread_setschedparam(thread, policy, &realparam);
}

static int darwin_my_pthread_attr_setschedparam(pthread_attr_t *__attr, struct bionic_sched_param const *param)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    struct sched_param realparam;
    pthread_attr_getschedparam(realattr, &realparam);
    realparam.sched_priority = param->sched_priority;
    return pthread_attr_setschedparam(realattr, &realparam);
}

static int darwin_my_pthread_attr_getschedparam(pthread_attr_t const *__attr, struct bionic_sched_param *param)
{
    pthread_attr_t *realattr = (pthread_attr_t *) *(unsigned int *) __attr;
    struct sched_param realparam;
    int ret = pthread_attr_getschedparam(realattr, &realparam);
    if (param != NULL)
        param->sched_priority = realparam.sched_priority;
    return ret;
}


#endif

#ifndef __APPLE__

static int my_sem_init(sem_t **sem, int pshared, unsigned int value) {
    *sem = (sem_t*) malloc(sizeof(sem_t));
    if (!(*sem)) {
        errno = ENOMEM;
        return -1;
    }
    int ret = sem_init(*sem, pshared, value);
    if (ret) {
        free(*sem);
        *sem = NULL;
    }
    return ret;
}

static int my_sem_destroy(sem_t **sem) {
    if (!(*sem))
        return 0;
    int ret = sem_destroy(*sem);
    free(*sem);
    *sem = NULL;
    return ret;
}

static int my_sem_wait(sem_t **sem) {
    return sem_wait(*sem);
}

static int my_sem_timedwait(sem_t **sem, const struct timespec *abs_timeout) {
    return sem_timedwait(*sem, abs_timeout);
}

static int my_sem_post(sem_t **sem) {
    return sem_post(*sem);
}

#else

struct darwin_my_sem_info {
    semaphore_t sem;
};
static int darwin_my_sem_init(struct darwin_my_sem_info **sem, int pshared, unsigned int value) {
    if (pshared) {
        printf("sem_init: pshared not supported\n");
    }
    *sem = malloc(sizeof(struct darwin_my_sem_info));
    kern_return_t res = semaphore_create(mach_task_self(), &(*sem)->sem, SYNC_POLICY_FIFO, value);
    if (res) {
        free(*sem);
        *sem = NULL;
        if (res == KERN_INVALID_ARGUMENT)
            errno = EINVAL;
        if (res == KERN_RESOURCE_SHORTAGE)
            errno = ENOMEM;
        return -1;
    }
    return 0;
}
static int darwin_my_sem_destroy(struct darwin_my_sem_info **sem) {
    semaphore_destroy(mach_task_self(), (*sem)->sem);
    free(*sem);
    return 0;
}
static int darwin_my_sem_wait(struct darwin_my_sem_info **sem) {
    return semaphore_wait((*sem)->sem);
}
static int darwin_my_sem_timedwait(struct darwin_my_sem_info **sem, const struct timespec *abs_timeout) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    mach_timespec_t ts;
    if  (abs_timeout->tv_sec > now.tv_sec ||
        (abs_timeout->tv_sec == now.tv_sec && abs_timeout->tv_nsec > now.tv_nsec)) {
        ts.tv_sec = (unsigned int) (abs_timeout->tv_sec - now.tv_sec);
        ts.tv_nsec = abs_timeout->tv_nsec - now.tv_nsec;
    } else {
        ts.tv_sec = 0;
        ts.tv_nsec = 0;
    }
    kern_return_t result = semaphore_timedwait((*sem)->sem, ts);
    if (result == KERN_SUCCESS)
        return 0;
    if (result == KERN_OPERATION_TIMED_OUT)
        errno = ETIMEDOUT;
    if (result == KERN_ABORTED)
        errno = EINTR;
    return -1;
}
static int darwin_my_sem_post(struct darwin_my_sem_info **sem) {
    return semaphore_signal((*sem)->sem);
}

#endif

struct _hook pthread_hooks[] = {
    /* pthread.h */
    // {"getauxval", getauxval},
    {"gettid", my_gettid},
    {"pthread_create", my_pthread_create},
    {"pthread_kill", pthread_kill},
    {"pthread_exit", pthread_exit},
    {"pthread_join", pthread_join},
    {"pthread_detach", pthread_detach},
    {"pthread_self", pthread_self},
    {"pthread_equal", pthread_equal},
#ifdef __APPLE__
    {"pthread_getschedparam", darwin_my_pthread_getschedparam},
    {"pthread_setschedparam", darwin_my_pthread_setschedparam},
#else
    {"pthread_getschedparam", pthread_getschedparam},
    {"pthread_setschedparam", pthread_setschedparam},
#endif
    {"pthread_mutex_init", my_pthread_mutex_init},
    {"pthread_mutex_destroy", my_pthread_mutex_destroy},
    {"pthread_mutex_lock", my_pthread_mutex_lock},
    {"pthread_mutex_unlock", my_pthread_mutex_unlock},
    {"pthread_mutex_trylock", my_pthread_mutex_trylock},
#ifdef __APPLE__
    {"pthread_mutexattr_init", darwin_my_pthread_mutexattr_init},
    {"pthread_mutexattr_destroy", darwin_my_pthread_mutexattr_destroy},
    {"pthread_mutexattr_gettype", darwin_my_pthread_mutexattr_gettype},
    {"pthread_mutexattr_settype", darwin_my_pthread_mutexattr_settype},
    {"pthread_mutexattr_getpshared", darwin_my_pthread_mutexattr_getpshared},
    {"pthread_mutexattr_setpshared", darwin_my_pthread_mutexattr_setpshared},
#else
    {"pthread_mutexattr_init", pthread_mutexattr_init},
    {"pthread_mutexattr_destroy", pthread_mutexattr_destroy},
    {"pthread_mutexattr_gettype", pthread_mutexattr_gettype},
    {"pthread_mutexattr_settype", pthread_mutexattr_settype},
    {"pthread_mutexattr_getpshared", pthread_mutexattr_getpshared},
    {"pthread_mutexattr_setpshared", pthread_mutexattr_setpshared},
#endif
    {"pthread_condattr_init", pthread_condattr_init},
    {"pthread_condattr_getpshared", pthread_condattr_getpshared},
    {"pthread_condattr_setpshared", pthread_condattr_setpshared},
    {"pthread_condattr_destroy", pthread_condattr_destroy},
    {"pthread_cond_init", my_pthread_cond_init},
    {"pthread_cond_destroy", my_pthread_cond_destroy},
    {"pthread_cond_broadcast", my_pthread_cond_broadcast},
    {"pthread_cond_signal", my_pthread_cond_signal},
    {"pthread_cond_wait", my_pthread_cond_wait},
    {"pthread_cond_timedwait", my_pthread_cond_timedwait},
    {"pthread_cond_timedwait_monotonic", my_pthread_cond_timedwait},
    {"pthread_cond_timedwait_monotonic_np", my_pthread_cond_timedwait},
    {"pthread_key_delete", pthread_key_delete},
    {"pthread_setname_np", pthread_setname_np},
#ifdef __APPLE__
    {"pthread_once", darwin_my_pthread_once},
#else
    {"pthread_once", pthread_once},
#endif
    {"pthread_key_create", pthread_key_create},
    {"pthread_setspecific", pthread_setspecific},
    {"pthread_getspecific", pthread_getspecific},
    {"pthread_attr_init", my_pthread_attr_init},
    {"pthread_attr_destroy", my_pthread_attr_destroy},
    {"pthread_attr_setdetachstate", my_pthread_attr_setdetachstate},
    {"pthread_attr_getdetachstate", my_pthread_attr_getdetachstate},
    // {"pthread_attr_setschedpolicy", my_pthread_attr_setschedpolicy},
    // {"pthread_attr_getschedpolicy", my_pthread_attr_getschedpolicy},
#ifdef __APPLE__
    {"pthread_attr_setschedparam", darwin_my_pthread_attr_setschedparam},
    {"pthread_attr_getschedparam", darwin_my_pthread_attr_getschedparam},
#else
    {"pthread_attr_setschedparam", my_pthread_attr_setschedparam},
    {"pthread_attr_getschedparam", my_pthread_attr_getschedparam},
#endif
    {"pthread_attr_setstacksize", my_pthread_attr_setstacksize},
    {"pthread_attr_getstacksize", my_pthread_attr_getstacksize},
    {"pthread_attr_setstack", my_pthread_attr_setstack},
    {"pthread_attr_getstack", my_pthread_attr_getstack},
    {"pthread_attr_setguardsize", my_pthread_attr_setguardsize},
    {"pthread_attr_getguardsize", my_pthread_attr_getguardsize},
    {"pthread_attr_setscope", my_pthread_attr_setscope},
    {"pthread_attr_getscope", my_pthread_attr_getscope},
    {"__pthread_cleanup_push", my_pthread_cleanup_push},
    {"__pthread_cleanup_pop", my_pthread_cleanup_pop},
    /* semaphore.h */
#ifndef __APPLE__
    {"sem_init", my_sem_init},
    {"sem_destroy", my_sem_destroy},
    {"sem_wait", my_sem_wait},
    {"sem_timedwait", my_sem_timedwait},
    {"sem_post", my_sem_post},
#else
    {"sem_init", darwin_my_sem_init},
    {"sem_destroy", darwin_my_sem_destroy},
    {"sem_wait", darwin_my_sem_wait},
    {"sem_timedwait", darwin_my_sem_timedwait},
    {"sem_post", darwin_my_sem_post},
#endif
    {NULL, NULL}
};
