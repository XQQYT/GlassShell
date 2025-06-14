#include "GlassShell/Driver/Pty/PtyDriver.h"

#include <fcntl.h>
#include <pty.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <iostream>
#include <string>

void PtyDriver::readFromPty() {
    char buffer[1024];
    while (running) {
        ssize_t count = read(m_masterFd, buffer, sizeof(buffer) - 1);
        if (count > 0) {
            if (m_callback && count) {
                m_callback(std::string(buffer, static_cast<size_t>(count)));
            }
        } else {
            break;
        }
    }
}

PtyDriver::PtyDriver(std::function<void(std::string)> output) {
    m_pid = forkpty(&m_masterFd, nullptr, nullptr, nullptr);
    if (m_pid < 0) {
        perror("forkpty failed");
        return;
    }

    if (m_pid == 0) {
        setenv("TERM", "xterm-256color", 1);
        execl("/bin/bash", "bash", nullptr);
        perror("execl failed");
        exit(1);
    } else {
        std::cout << "Child PID: " << m_pid << std::endl;
        running = true;
        m_readThread = std::thread(&PtyDriver::readFromPty, this);
    }
    m_callback = output;
}

PtyDriver::~PtyDriver() {
    running = false;
    close(m_masterFd);
    waitpid(m_pid, nullptr, 0);
    m_readThread.join();
}

bool isProcessAlive(pid_t pid) { return (kill(pid, 0) == 0 || errno != ESRCH); }

void PtyDriver::input(const std::string str) {
    if (str.empty()) {
        std::cout << "empty" << std::endl;
        return;
    }
    if (!isProcessAlive(m_pid)) {
        std::cout << "process dead" << std::endl;
        return;
    }
    write(m_masterFd, str.c_str(), str.size());
}