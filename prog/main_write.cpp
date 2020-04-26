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
    for (int i = 0; i < id * 1000000; i++) fileout << "Hello world";
    out_file << fileout.str() << std::endl;
    out_file.close();
}

int main() {
    for (int t = 0; t < 4; t++) {
        std::vector<std::thread> threads;
        for (int i = 0; i < 8; i++) threads.emplace_back(big_work, i);
        for (auto &thread : threads) thread.join();
    }
    return 0;
}
