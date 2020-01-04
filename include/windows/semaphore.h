#pragma once
#include <msvc.h>
#include <time.h>

typedef HANDLE sem_t;

int sem_init(sem_t *sem, int pshared, unsigned int value) {
    *sem = CreateSemaphoreA(NULL, value, 10, NULL);
    return *sem != (sem_t)-1;
}

int sem_destroy(sem_t *sem) {
    return !CloseHandle(*sem);
}

int sem_wait(sem_t *sem) {
    return WaitForSingleObject(*sem, INFINITE) != WAIT_OBJECT_0;
}

int sem_trywait(sem_t *sem) {
    return WaitForSingleObject(*sem, 0) != WAIT_OBJECT_0;
}

int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout) {
    return WaitForSingleObject(*sem, abs_timeout->tv_sec + abs_timeout->tv_nsec / 1000000) != WAIT_OBJECT_0;
}

int sem_post(sem_t *sem) {
    return ReleaseSemaphore(*sem, 1, NULL);
}