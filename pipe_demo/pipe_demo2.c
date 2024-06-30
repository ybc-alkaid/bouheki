#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define BUFFER_SIZE 100

int main() {
    // 管道1用于父进程向子进程发送消息,管道2用于子进程向父进程发送消息	
    int pipefd1[2], pipefd2[2];
    pid_t cpid;
    char parent_msg[] = "Message from parent";
    char child_msg[] = "Message from child";
    char buffer[BUFFER_SIZE];

    // 创建两个管道
    if (pipe(pipefd1) == -1 || pipe(pipefd2) == -1) {
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
        close(pipefd1[1]);  // 关闭第一个管道的写端
        close(pipefd2[0]);  // 关闭第二个管道的读端

        // 从第一个管道读取数据
        read(pipefd1[0], buffer, BUFFER_SIZE);
        printf("Child received: %s\n", buffer);

        // 向第二个管道写入数据
        write(pipefd2[1], child_msg, strlen(child_msg) + 1);

        close(pipefd1[0]);
        close(pipefd2[1]);

        return 0;
    } else {  // 父进程
        close(pipefd1[0]);  // 关闭第一个管道的读端
        close(pipefd2[1]);  // 关闭第二个管道的写端

        // 向第一个管道写入数据
        write(pipefd1[1], parent_msg, strlen(parent_msg) + 1);

        // 从第二个管道读取数据
        read(pipefd2[0], buffer, BUFFER_SIZE);
        printf("Parent received: %s\n", buffer);

        close(pipefd1[1]);
        close(pipefd2[0]);

        // 等待子进程结束
        wait(NULL);
        return 0;
    }
}

