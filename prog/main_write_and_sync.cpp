#include <cstdlib>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

void __attribute__((noinline)) big_work(int id) {
	std::ofstream out_file("out/" + std::to_string(id) + ".txt");
	std::stringstream fileout;
	for (int i = 0; i < id * 5000; i++) fileout << "Hello world";
	out_file << fileout.str() << std::endl;
	out_file.flush();
	out_file.close();
}

void work(int id) {
    big_work(id);
}

void stupid_work(int id) {
	static std::mutex work_mutex;
	std::lock_guard<std::mutex> l(work_mutex);
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

int main() {
	std::this_thread::sleep_for(std::chrono::seconds(1));
	std::vector<std::thread> threads;

	for (int i = 0; i < 30; i++) {
		threads.emplace_back(work, i);
	}

	for (auto &thread : threads) thread.join();
	threads.clear();

	for (int i = 0; i < 30; i++) {
		threads.emplace_back(stupid_work, i);
	}

	for (auto &thread : threads) thread.join();

    return 0;
}
