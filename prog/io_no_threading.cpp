#include <cstdlib>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

int main() {
    std::string result = "";

    for (int i = 0; i < 250000000; i++) {
        result += i;
    }

    std::ofstream out_file("out/test_write.txt");
    out_file << result << std::endl;
    out_file.flush();
    out_file.close();

    return 0;
}
