#pragma once

#include <condition_variable>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <set>
#include <string>

// ===================================================================
// Fan-out for the alert stream: ONE Kafka consumer thread publishes alerts to
// MANY connected gRPC clients, each of which drains its own queue.
//
// New C++ territory: threads share data, so every access to shared state is
// protected by a mutex (a lock — only one thread holds it at a time). A
// condition_variable lets a consumer SLEEP until data arrives instead of busy-
// looping, and be woken when push() happens.
// ===================================================================

// One subscriber's inbox: a thread-safe queue of serialized alert JSON strings.
class ClientQueue {
public:
    void push(const std::string& msg) {
        {
            std::lock_guard<std::mutex> lk(m_);   // lock for the duration of the block
            q_.push_back(msg);
        }
        cv_.notify_one();                          // wake a waiting pop()
    }

    // Wait up to `timeout` for the next message. Returns false on timeout/close
    // (so the caller can re-check whether the client is still connected).
    bool pop(std::string& out, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lk(m_);
        // Sleep until there's data or we're closed, or timeout elapses.
        if (!cv_.wait_for(lk, timeout, [&] { return !q_.empty() || closed_; }))
            return false;
        if (q_.empty()) return false;
        out = std::move(q_.front());
        q_.pop_front();
        return true;
    }

    void close() {
        {
            std::lock_guard<std::mutex> lk(m_);
            closed_ = true;
        }
        cv_.notify_all();
    }

private:
    std::mutex              m_;
    std::condition_variable cv_;
    std::deque<std::string> q_;
    bool                    closed_ = false;
};

// Registry of connected clients. publish() fans an alert out to all of them.
class AlertBroadcaster {
public:
    std::shared_ptr<ClientQueue> subscribe() {
        auto q = std::make_shared<ClientQueue>();
        std::lock_guard<std::mutex> lk(m_);
        clients_.insert(q);
        return q;
    }

    void unsubscribe(const std::shared_ptr<ClientQueue>& q) {
        std::lock_guard<std::mutex> lk(m_);
        clients_.erase(q);
    }

    void publish(const std::string& msg) {
        std::lock_guard<std::mutex> lk(m_);
        for (const auto& q : clients_) q->push(msg);
    }

    std::size_t client_count() {
        std::lock_guard<std::mutex> lk(m_);
        return clients_.size();
    }

private:
    std::mutex m_;
    std::set<std::shared_ptr<ClientQueue>> clients_;
};