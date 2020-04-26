//
// Created by Ashley Davies-Lyons on 2019-02-07.
//

#include <iostream>
#include <linux/futex.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <cstdlib>
#include <mutex>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

using namespace std;

void wake(int *addr) {
    // Sleep to ensure the futex call isn't redundant at runtime
    this_thread::sleep_for(chrono::milliseconds(1000));

    // Wake the main thread
    *addr = 1;
    syscall(SYS_futex, addr, FUTEX_WAKE, 1);

    // Sleep to ensure `other.join()` results in a futex operation
    this_thread::sleep_for(chrono::milliseconds(1000));
}

int main(void) {
    static int futex_a = 0;
    thread other(wake, &futex_a);
    syscall(SYS_futex, &futex_a, FUTEX_WAIT, 0, NULL);
    other.join();
    return 0;
}
