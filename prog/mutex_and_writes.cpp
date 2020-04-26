#include <cstdlib>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

void __attribute__((noinline)) mutex_work(int id) {
    static std::mutex work_mutex;
    std::lock_guard<std::mutex> l(work_mutex);

    std::this_thread::sleep_for(std::chrono::milliseconds(250));
}

void __attribute__((noinline)) write_file(int id, std::string out) {
    std::ofstream out_file("out/" + std::to_string(id) + ".txt");
    for (int i = 0; i < id; i++) out_file << out << std::endl;
    out_file.close();
}

int main() {
    std::stringstream fileout;
    for (int i = 0; i < 1000000; i++) fileout << i;
    std::string str = fileout.str();

    std::vector<std::thread> threads{};

    for (int i = 0; i < 10; i++) {
        for (int t = 0; t < 16; t++) {
            threads.emplace_back(mutex_work, t);
        }

        for (auto &thread : threads) thread.join();
        threads.clear();
    }

    for (int t = 0; t < 12; t++) {
        threads.emplace_back(write_file, t, str);
    }

    for (auto &thread : threads) thread.join();

    return 0;
}
