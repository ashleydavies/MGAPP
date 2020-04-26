#include <cstdlib>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

static std::mutex work_mutex;

void __attribute__((noinline)) big_work(int id) {
	std::lock_guard<std::mutex> l(work_mutex);
	volatile int x = 5;
	for (int i = 0; i < id * 10000000; i++) {
		if (i % 6 == 0 && i % 8 == 0 && i % 10 == 0 && i % 32 == 0 && i % 46 == 0) {
			// Magic hacks
			x++;
		}
	}
}

void __attribute__((noinline)) medium_work(int id) {
	std::lock_guard<std::mutex> l(work_mutex);
	volatile int x = 5;
	for (int i = 0; i < id * 25000; i++) {
		if (i % 6 == 0 && i % 8 == 0 && i % 10 == 0 && i % 32 == 0 && i % 46 == 0) {
			// Magic hacks
			x++;
		}
	}
}

void __attribute__((noinline)) small_work(int id) {
	std::lock_guard<std::mutex> l(work_mutex);
	volatile int x = 5;
	for (int i = 0; i < id * 5000; i++) {
		if (i % 6 == 0 && i % 8 == 0 && i % 10 == 0 && i % 32 == 0 && i % 46 == 0) {
			// Magic hacks
			x++;
		}
	}
}

void random_work(int id) {
	for (int i = 0; i < 10; i++) {
		int r = rand() % 100;
		if (r < 33) {
			small_work(id);
		} else if (r < 66) {
			medium_work(id);
		} else {
			big_work(id);
		}
	}
}

int main() {
	std::this_thread::sleep_for(std::chrono::seconds(1));
	for (int t = 0; t < 8; t++) {
        std::vector<std::thread> threads;

        for (int i = 0; i < 18; i++) {
            threads.emplace_back(random_work, i);
        }

        for (auto &thread : threads) thread.join();
	}

    std::this_thread::sleep_for(std::chrono::seconds(1));

    return 0;
}
