#include <cstdlib>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

void mutex_work(int id) {
    static std::mutex work_mutex;
    std::lock_guard<std::mutex> l(work_mutex);

    std::this_thread::sleep_for(std::chrono::milliseconds(250));
}

int main() {
    std::vector<std::thread> threads{};

    for (int t = 0; t < 12; t++) {
        threads.emplace_back(mutex_work, t);
    }

    for (auto &thread : threads) thread.join();

    return 0;
}
