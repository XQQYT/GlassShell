#pragma once

#include <stdint.h>
#include <thread>
#include <functional>
#include <atomic>

class PtyDriver {
    public:
        PtyDriver(std::function<void(std::string)> output);
        ~PtyDriver();
        void input(const std::string str);
    private:
        void readFromPty();
    private:
        static uint32_t s_nextPtyId;
        uint32_t m_ptyId;
        int m_masterFd;
        std::thread m_readThread;
        pid_t m_pid;
        std::function<void(std::string)> m_callback;
        std::atomic<bool> running;
};