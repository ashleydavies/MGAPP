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

void __attribute__((noinline)) write_file(int id, std::string out) {
    std::ofstream out_file("out/" + std::to_string(id) + ".txt");
    for (int i = 0; i < id; i++) out_file << out << std::endl;
    out_file.close();
}

int main() {
    std::stringstream fileout;
    for (int i = 0; i < 1000000; i++) fileout << i;
    std::string str = fileout.str();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    for (int n = 0; n < 2; n++) {
        std::vector<std::thread> threads;

        for (int i = 11; i >= 0; i--) {
            threads.emplace_back(write_file, i * n + i, str);
        }

        for (auto &thread : threads) thread.join();
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    return 0;
}
