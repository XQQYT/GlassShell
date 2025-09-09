
#include <iostream>
#include <unistd.h>
#include <termios.h>
#include <pty.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <string>
#include <thread>

void readFromPty(int master_fd) {
    char buffer[1024];
    while (true) {
        ssize_t count = read(master_fd, buffer, sizeof(buffer) - 1);
        if (count > 0) {
            buffer[count] = '\0';
            std::cout << "output: "<<buffer << std::flush;
        } else {
            break;
        }
    }
}

int main() {
    int master_fd;
    pid_t pid = forkpty(&master_fd, nullptr, nullptr, nullptr);
    if (pid < 0) {
        perror("forkpty failed");
        return 1;
    }

    if (pid == 0) {
        execl("/bin/bash", "bash", nullptr);
        perror("execl failed");
        exit(1);
    } else {
        std::cout << "Child PID: " << pid << std::endl;

        std::thread reader(readFromPty, master_fd);

        std::string input;
        while (true) {
            std::getline(std::cin, input);
            input += "\n";
            if (input == "exit\n") break;
            write(master_fd, input.c_str(), input.size());
        }

        close(master_fd);
        waitpid(pid, nullptr, 0);
        reader.join();
    }

    return 0;
}