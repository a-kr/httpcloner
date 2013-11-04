#ifndef QUEUES_H
#define QUEUES_H

#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <chrono>
#include <functional>
#include <condition_variable>

/*
template<typename T> class LockingQueue : public Queue<T> {
private:
    std::mutex m;
    std::condition_variable condvar;
    std::mutex condvar_m;
    std::queue<T> q;
public:
    virtual void put(T x) {
        this->m.lock();
        this->q.push(x);
        this->m.unlock();
        this->condvar.notify_one();
    }
    virtual void startwork() {
        this->m.lock();
    }
    virtual T get() {
        T x;
        x = this->q.front();
        this->q.pop();
        return x;
    }
    virtual void endwork() {
        this->m.unlock();
    }
    virtual void wait() {
        std::unique_lock<std::mutex> lk(this->condvar_m);
        this->condvar.wait(lk);
    }
    virtual bool empty() {
        bool e;
        e = q.empty();
        return e;
    }
};

*/

template<typename T> class SwitchingQueue {
private:
    std::mutex m;
    std::condition_variable condvar;
    std::mutex condvar_m;
    std::queue<T> *q;
    std::queue<T> *q_back;
    std::queue<T> *q_front;
public:
    SwitchingQueue() {
        this->q = new std::queue<T>();
        this->q_back = new std::queue<T>();
        this->q_front = new std::queue<T>();
    }
    void put(T x) {
        this->q_front->push(x);
    }
    void put_and_commit_if_N(T x, int n) {
        this->q_front->push(x);
        if (this->q_front->size() >= n) {
            this->commit();
        }
    }
    void commit() {
        this->m.lock();
        std::queue<T> *tmp = this->q_front;
        this->q_front = this->q;
        this->q = tmp;
        this->m.unlock();
        this->condvar.notify_one();
    }
    void startwork() {
        this->m.lock();
        std::queue<T> *tmp = this->q;
        this->q = this->q_back;
        this->q_back = tmp;
        this->m.unlock();
    }
    T get() {
        T x;
        x = this->q_back->front();
        this->q_back->pop();
        return x;
    }
    void endwork() {
    }
    void wait() {
        std::unique_lock<std::mutex> lk(this->condvar_m);
        this->condvar.wait(lk);
    }
    void wait_for(std::chrono::milliseconds &d) {
        std::unique_lock<std::mutex> lk(this->condvar_m);
        this->condvar.wait_for(lk, d);
    }
    bool empty() {
        bool e;
        e = this->q_back->empty();
        return e;
    }
};

template<typename T> class AtomicSwitchingQueue {
private:
    std::condition_variable condvar;
    std::mutex condvar_m;
    std::atomic<std::queue<T> *> aq;
    std::queue<T> *q_back;
    std::queue<T> *q_front;
public:
    AtomicSwitchingQueue() {
        auto q = new std::queue<T>();
        this->aq.store(q);
        this->q_back = new std::queue<T>();
        this->q_front = new std::queue<T>();
    }
    void put(T x) {
        this->q_front->push(x);
    }
    void put_and_commit_if_N(T x, int n) {
        this->q_front->push(x);
        if (this->q_front->size() >= n) {
            this->commit();
        }
    }
    void commit() {
        this->q_front = std::atomic_exchange(&this->aq, this->q_front);
        this->condvar.notify_one();
    }
    void startwork() {
        this->q_back = std::atomic_exchange(&this->aq, this->q_back);
    }
    T get() {
        T x;
        x = this->q_back->front();
        this->q_back->pop();
        return x;
    }
    void endwork() {
    }
    void wait() {
        std::unique_lock<std::mutex> lk(this->condvar_m);
        this->condvar.wait(lk);
    }
    void wait_for(std::chrono::milliseconds &d) {
        std::unique_lock<std::mutex> lk(this->condvar_m);
        this->condvar.wait_for(lk, d);
    }
    bool empty() {
        bool e;
        e = this->q_back->empty();
        return e;
    }
};

#endif
