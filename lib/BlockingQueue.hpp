#ifndef DNS_BLOCKINGQUEUE_HPP
#define DNS_BLOCKINGQUEUE_HPP
#include <queue>
#include <mutex>
#include <condition_variable>
template <typename T>
class BlockingQueue {
private:

    std::queue<T> queue;
    std::mutex mutex;
    std::condition_variable cv;
public:
    BlockingQueue();
    BlockingQueue(const BlockingQueue& )=delete;
    void push(const T& value) {
        {
            std::unique_lock<std::mutex> lock(mutex);
            queue.push(value);
        }
        cv.notify_all();
    }
    void push(T&& value) {
        {
            std::unique_lock<std::mutex> lock(mutex);
            queue.push(std::move(value));
        }
        cv.notify_all();
    }
    T pop() {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return !queue.empty(); });
        T front = queue.front();
        queue.pop();
        return front;
    }
    size_t size(){
        std::unique_lock<std::mutex> lock(mutex);
        return queue.size();
    }
};

#endif
