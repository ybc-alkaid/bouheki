#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define BUFFER_SIZE 100

int main() {
    int pipefd[2];
    pid_t cpid;
    char buffer[BUFFER_SIZE];

    // 创建管道,pipefd[0]是读端,pipefd[1]是写端
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    // 创建子进程
    cpid = fork();
    if (cpid == -1) {
        perror("fork");
        return 1;
    }

    if (cpid == 0) {  // 子进程
        close(pipefd[0]);  // 关闭读端

        // 重定向标准输出到管道的写端
        if (dup2(pipefd[1], STDOUT_FILENO) == -1) {
            perror("dup2");
            return 1;
        }
        close(pipefd[1]);

        // 执行命令
        // execlp("echo", "echo", "Hello, eBPF!", NULL);
        // perror("execlp");
        printf("Hello, eBPFFF!");
        return 1;
    } 
    else {  // 父进程
        close(pipefd[1]);  // 关闭写端

        // 从管道读取数据
        read(pipefd[0], buffer, BUFFER_SIZE);
        printf("Received from child: %s\n", buffer);
        close(pipefd[0]);

        // 等待子进程结束
        wait(NULL);
        return 0;
    }
}

