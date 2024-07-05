#include <iostream>
#include <thread>
#include <vector>
#include <cstdlib>

const size_t ARRAY_SIZE = 10000000; // Size of the array each thread will allocate

void memoryIntensiveTask(int threadID) {
    // Allocate a large array
    std::vector<int> largeArray(ARRAY_SIZE);

    // Perform some operations on the array
    for (size_t i = 0; i < ARRAY_SIZE; ++i) {
        largeArray[i] = rand() % 100;
    }

    // Calculate the sum of the array
    long long sum = 0;
    for (size_t i = 0; i < ARRAY_SIZE; ++i) {
        sum += largeArray[i];
    }

    std::cout << "Thread " << threadID << " completed. Sum: " << sum << std::endl;
}

int main() {
    const int numThreads = 5;
    std::vector<std::thread> threads;

    // Launch the threads
    for (int i = 0; i < numThreads; ++i) {
        threads.push_back(std::thread(memoryIntensiveTask, i));
    }

    // Join the threads with the main thread
    for (auto& thread : threads) {
        thread.join();
    }

    std::cout << "All threads completed." << std::endl;
    return 0;
}