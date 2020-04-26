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

// This hack makes g++ generate the symbol name as-is without random C++ junk
// i.e. `startf` instead of e.g. `_Z5startfv` in the binary headers
extern "C" {
void startf(int id) { id++; }
void endf(int id) { id++; }
}

void __attribute__((noinline)) big_work(int id) {
	std::ofstream out_file("out/" + std::to_string(id) + ".txt");
	std::stringstream fileout;
	for (int i = 0; i < id * 50000; i++) fileout << "Hello world";
	out_file << fileout.str() << std::endl;
	out_file.close();
}

void mutex_work(int id) {
	static std::mutex work_mutex;

	std::lock_guard<std::mutex> l(work_mutex);

	startf(id);
	std::stringstream out;
	out << id << " starting work.";

    big_work(id);

	//std::cout << out.str() << std::endl;
	do_work();
	out.str("");
	out << id << " finished work.";
	endf(id);
	//if (rand() % 100 > id * 10) mutex_work(id);
	//std::cout << out.str() << std::endl;
}

int main() {
	std::this_thread::sleep_for(std::chrono::seconds(1));
	for (int i = 0; i < 10; i++) {
	std::vector<std::thread> threads;

	for (int i = 0; i < 3; i++) {
		threads.emplace_back(mutex_work, i);
	}

	mutex_work(100);

	for (auto &thread : threads) thread.join();
	}

    std::this_thread::sleep_for(std::chrono::seconds(1));

    return 0;
}
