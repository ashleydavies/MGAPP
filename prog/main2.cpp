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
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    *addr = 1;
    syscall(SYS_futex, addr, FUTEX_WAKE, 1);
}

int main(void) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    cout << "Hello" << endl;
    static int futex_a = 0;
    cout << &futex_a << endl;
    std::thread other(wake, &futex_a);
    syscall(SYS_futex, &futex_a, FUTEX_WAIT, 0, NULL);
    cout << "Woke" << endl;
}
