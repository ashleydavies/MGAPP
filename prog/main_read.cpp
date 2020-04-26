#include <cstdlib>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

void __attribute__((noinline)) big_work(int id) {
    std::ifstream file("in/hello" + std::to_string((id % 4) + 1) + ".txt");
    char *buffer = new char[250 * 1024 * 1024];
    file.read(buffer, 250 * 1024 * 1024);
    file.close();
}

int main() {
    for (int t = 0; t < 4; t++) {
        std::vector<std::thread> threads;
        for (int i = 0; i < 8; i++) threads.emplace_back(big_work, i);
        for (auto &thread : threads) thread.join();
    }
    return 0;
}
