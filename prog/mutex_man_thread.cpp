#include <cstdlib>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

#define STACK_SIZE 4096
static std::mutex work_mutex;

int mutex_work(void *_) {
    std::lock_guard<std::mutex> l(work_mutex);

    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    return 0;
}

int main() {
    for (int t = 0; t < 12; t++) {
        char *child_stack = (char*) malloc(STACK_SIZE);
        clone(&mutex_work, child_stack+STACK_SIZE, CLONE_SIGHAND|CLONE_FS|CLONE_VM|CLONE_FILES|CLONE_THREAD, 0);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    return 0;
}
