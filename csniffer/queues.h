#ifndef QUEUES_H
#define QUEUES_H

#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <chrono>
#include <functional>
#include <condition_variable>

template<typename T> class Queue {
public:
    virtual void put(T x) = 0;
    virtual void startwork() = 0;
    virtual T get() = 0;
    virtual void endwork() = 0;
    virtual void wait() = 0;
    virtual bool empty() = 0;
};

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


template<typename T> class SwitchingQueue : public Queue<T> {
private:
    std::mutex m;
    std::condition_variable condvar;
    std::mutex condvar_m;
    std::queue<T> *q;
    std::queue<T> *q_back;
public:
    SwitchingQueue() {
        this->q = new std::queue<T>();
        this->q_back = new std::queue<T>();
    }
    virtual void put(T x) {
        this->m.lock();
        std::queue<T> *tmp = this->q;
        tmp->push(x);
        this->m.unlock();

        this->condvar.notify_one();
    }
    virtual void putmany(std::queue<T> &xx) {
        this->m.lock();
        std::queue<T> *tmp = this->q;
        while (!xx.empty()) {
            tmp->push(xx.front());
            xx.pop();
        }
        this->m.unlock();

        this->condvar.notify_one();
    }
    virtual void startwork() {
        this->m.lock();
        std::queue<T> *tmp = this->q;
        this->q = this->q_back;
        this->q_back = tmp;
        this->m.unlock();
    }
    virtual T get() {
        T x;
        x = this->q_back->front();
        this->q_back->pop();
        return x;
    }
    virtual void endwork() {
    }
    virtual void wait() {
        std::unique_lock<std::mutex> lk(this->condvar_m);
        this->condvar.wait(lk);
    }
    virtual void wait_for(std::chrono::milliseconds &d) {
        std::unique_lock<std::mutex> lk(this->condvar_m);
        this->condvar.wait_for(lk, d);
    }
    virtual bool empty() {
        bool e;
        e = this->q_back->empty();
        return e;
    }
};

#endif
