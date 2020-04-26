#include <cstdlib>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>
#include "tbb/tbb.h"
#include "tbb/parallel_for.h"
#include "tbb/mutex.h"

int main() {
    tbb::mutex work_mutex;
    tbb::parallel_for(0u, 100u, [&](unsigned n) {
        work_mutex.lock();
        int count = 0;
        for (unsigned i = 0; i < 100000000; i++) {
            if (n > i || i % 10000 == 0) {
                count++;
            }
        }
        work_mutex.unlock();
    });
    return 0;
}
