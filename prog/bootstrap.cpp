#include <unistd.h>
#include <cstdlib>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>

int main(int argc, char **argv) {
    std::cout << "Bootstrapping " << argv[1] << "; waiting 2 seconds first for BPF probes to initialise." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(2));

    char *pArgs[argc];

    // Don't copy the first argument, which is the application to bootstrap
    for (int i = 1; i < argc; i++) {
        pArgs[i - 1] = argv[i];
    }

    pArgs[argc - 1] = NULL;

    execvp(pArgs[0], pArgs);

    return 0;
}
