#include <cstdlib>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

void do_work() {
	std::this_thread::sleep_for(std::chrono::milliseconds(250));
}

void mutex_work(int id) {
	static std::mutex work_mutex;

	std::lock_guard<std::mutex> l(work_mutex);
	do_work();
}

int main() {
    std::vector<std::thread> threads;

    for (int i = 0; i < 2; i++) {
        threads.emplace_back(mutex_work, i);
    }

    mutex_work(100);

    for (auto &thread : threads) thread.join();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    return 0;
}
