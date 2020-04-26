//
// Adapted from:
//   https://stackoverflow.com/questions/1383363/is-my-spin-lock-implementation-correct-and-optimal
//

#include <malloc.h>
#include <stdio.h>
#include <pthread.h>

volatile int exclusion = 0;

void lock() {
    while (__sync_lock_test_and_set(&exclusion, 1)) {
        // Do nothing. This GCC builtin instruction
        // ensures memory barrier.
    }
}

void unlock() {
    __sync_synchronize(); // Memory barrier.
    exclusion = 0;
}

void *do_work(void *idp) {
    int id = *(int*) idp;
    lock();
    // Do some work to pass the time
    for (int i = 0; i < 5000000; i++) {
        volatile int x = 0;
        x++;
    }
    printf("Thread %d finished\n", id);
    unlock();
    return NULL;
}

int main() {

    pthread_t thread_id;

    for (int i = 0; i < 16; i++) {
        int *x = malloc(4);
        *x = i;
        pthread_create(&thread_id, NULL, do_work, (void *) x);
    }

    lock();
    unlock();

    return 0;

}

