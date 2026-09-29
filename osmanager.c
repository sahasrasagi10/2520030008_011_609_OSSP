#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include "osmanager.h"

#define MAX_INPUT 256
#define MAX_ARGS 20
#define MAX_HISTORY 50

static pid_t childPID = -1;
static int childCreated = 0;
static int childAlive = 0;

static int parentToChild[2];
static int childToParent[2];

static char history[MAX_HISTORY][MAX_INPUT];
static int historyCount = 0;

static void addHistory(const char *command)
{
    if (strlen(command) == 0)
        return;

    if (historyCount < MAX_HISTORY)
    {
        strcpy(history[historyCount], command);
        historyCount++;
    }
    else
    {
        for (int i = 0; i < MAX_HISTORY - 1; i++)
            strcpy(history[i], history[i + 1]);

        strcpy(history[MAX_HISTORY - 1], command);
    }
}

static void printHelp(void)
{
    printf("\nAvailable commands:\n");
    printf("---------------------------------------------\n");
    printf("execute <command>   Execute a Linux command\n");
    printf("create              Create a worker process\n");
    printf("status              Show worker process status\n");
    printf("message <text>      Send message to worker\n");
    printf("task <number>       Give computation task\n");
    printf("result              Show completed task result\n");
    printf("stop                Stop worker process\n");
    printf("resume              Resume worker process\n");
    printf("terminate           Terminate worker process\n");
    printf("history             Show command history\n");
    printf("clear               Clear terminal\n");
    printf("help                Show available commands\n");
    printf("exit                Exit program\n");
    printf("---------------------------------------------\n");
}

static char getProcessState(pid_t pid)
{
    char path[100];
    char line[256];
    char state = '?';

    FILE *file;

    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    file = fopen(path, "r");

    if (file == NULL)
        return '?';

    while (fgets(line, sizeof(line), file))
    {
        if (strncmp(line, "State:", 6) == 0)
        {
            sscanf(line, "State:\t%c", &state);
            break;
        }
    }

    fclose(file);

    return state;
}

static void showProcessStatus(void)
{
    char path[100];
    char line[256];

    char name[100] = "Unknown";
    char ppid[30] = "Unknown";
    char state = '?';

    FILE *file;

    if (!childCreated || !childAlive)
    {
        printf("\nNo active worker process is currently being managed.\n");
        return;
    }

    snprintf(path, sizeof(path), "/proc/%d/status", childPID);

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nWorker process no longer exists.\n");
        childAlive = 0;
        return;
    }

    while (fgets(line, sizeof(line), file))
    {
        if (strncmp(line, "Name:", 5) == 0)
        {
            sscanf(line, "Name:\t%99s", name);
        }
        else if (strncmp(line, "PPid:", 5) == 0)
        {
            sscanf(line, "PPid:\t%29s", ppid);
        }
        else if (strncmp(line, "State:", 6) == 0)
        {
            sscanf(line, "State:\t%c", &state);
        }
    }

    fclose(file);

    printf("\n========================================\n");
    printf("          PROCESS INFORMATION\n");
    printf("========================================\n");
    printf("PID   : %d\n", childPID);
    printf("PPID  : %s\n", ppid);
    printf("Name  : %s\n", name);
    printf("State : %c", state);

    if (state == 'R')
        printf(" (Running/Runnable)\n");
    else if (state == 'S')
        printf(" (Sleeping)\n");
    else if (state == 'T')
        printf(" (Stopped)\n");
    else if (state == 'Z')
        printf(" (Zombie)\n");
    else
        printf(" (Other)\n");
}

static void childProcess(void)
{
    char buffer[MAX_INPUT];
    char response[MAX_INPUT + 150];

    close(parentToChild[1]);
    close(childToParent[0]);

    while (1)
    {
        ssize_t bytes;

        bytes = read(
            parentToChild[0],
            buffer,
            sizeof(buffer) - 1
        );

        if (bytes <= 0)
            break;

        buffer[bytes] = '\0';

        if (strncmp(buffer, "MESSAGE:", 8) == 0)
        {
            snprintf(
                response,
                sizeof(response),
                "Worker received: %s",
                buffer + 8
            );

            write(
                childToParent[1],
                response,
                strlen(response) + 1
            );
        }
        else if (strncmp(buffer, "TASK:", 5) == 0)
        {
            unsigned long long limit;
            unsigned long long sum = 0;

            limit = strtoull(buffer + 5, NULL, 10);

            for (unsigned long long i = 1; i <= limit; i++)
            {
                sum += i;
            }

            snprintf(
                response,
                sizeof(response),
                "Task completed. Sum from 1 to %llu = %llu",
                limit,
                sum
            );

            write(
                childToParent[1],
                response,
                strlen(response) + 1
            );
        }
    }

    close(parentToChild[0]);
    close(childToParent[1]);

    _exit(0);
}

static void createChild(void)
{
    if (childCreated && childAlive)
    {
        printf("\nA worker process is already running.\n");
        printf("PID: %d\n", childPID);
        return;
    }

    if (pipe(parentToChild) == -1)
    {
        perror("Pipe creation failed");
        return;
    }

    if (pipe(childToParent) == -1)
    {
        perror("Pipe creation failed");

        close(parentToChild[0]);
        close(parentToChild[1]);

        return;
    }

    childPID = fork();

    if (childPID < 0)
    {
        perror("fork failed");

        close(parentToChild[0]);
        close(parentToChild[1]);
        close(childToParent[0]);
        close(childToParent[1]);

        return;
    }

    if (childPID == 0)
    {
        childProcess();
    }

    close(parentToChild[0]);
    close(childToParent[1]);

    childCreated = 1;
    childAlive = 1;

    printf("\n========================================\n");
    printf("       WORKER PROCESS CREATED\n");
    printf("========================================\n");
    printf("Parent PID : %d\n", getpid());
    printf("Worker PID : %d\n", childPID);
}

static void sendMessage(const char *message)
{
    char command[MAX_INPUT];
    char response[MAX_INPUT + 150];

    if (!childCreated || !childAlive)
    {
        printf("\nNo active worker process.\n");
        printf("Use 'create' first.\n");
        return;
    }

    if (getProcessState(childPID) == 'T')
    {
        printf("\nWorker process is stopped.\n");
        printf("Resume it before sending a message.\n");
        return;
    }

    snprintf(command, sizeof(command), "MESSAGE:%s", message);

    if (write(
            parentToChild[1],
            command,
            strlen(command) + 1
        ) == -1)
    {
        perror("Failed to send message");
        return;
    }

    ssize_t bytes = read(
        childToParent[0],
        response,
        sizeof(response) - 1
    );

    if (bytes > 0)
    {
        response[bytes] = '\0';
        printf("\nResponse: %s\n", response);
    }
}

static void sendTask(const char *value)
{
    char command[MAX_INPUT];

    if (!childCreated || !childAlive)
    {
        printf("\nNo active worker process.\n");
        printf("Use 'create' first.\n");
        return;
    }

    char state = getProcessState(childPID);

    if (state == '?')
    {
        printf("\nWorker process no longer exists.\n");
        childAlive = 0;
        return;
    }

    if (state == 'T')
    {
        printf("\nWorker process is stopped.\n");
        printf("Resume it before sending a task.\n");
        return;
    }

    unsigned long long number = strtoull(value, NULL, 10);

    if (number == 0)
    {
        printf("\nEnter a number greater than 0.\n");
        return;
    }

    snprintf(command, sizeof(command), "TASK:%llu", number);

    if (write(
            parentToChild[1],
            command,
            strlen(command) + 1
        ) == -1)
    {
        perror("Failed to send task");
        return;
    }

    printf("\nTask sent to worker.\n");
    printf("Worker is performing the computation.\n");
}

static void getResult(void)
{
    char response[MAX_INPUT + 150];

    if (!childCreated || !childAlive)
    {
        printf("\nNo active worker process.\n");
        return;
    }

    int flags = fcntl(childToParent[0], F_GETFL, 0);

    if (flags == -1)
    {
        perror("fcntl");
        return;
    }

    if (fcntl(
            childToParent[0],
            F_SETFL,
            flags | O_NONBLOCK
        ) == -1)
    {
        perror("fcntl");
        return;
    }

    ssize_t bytes = read(
        childToParent[0],
        response,
        sizeof(response) - 1
    );

    fcntl(childToParent[0], F_SETFL, flags);

    if (bytes > 0)
    {
        response[bytes] = '\0';
        printf("\n%s\n", response);
    }
    else
    {
        printf("\nTask is still running or no result is available yet.\n");
    }
}

static void stopChild(void)
{
    if (!childCreated || !childAlive)
    {
        printf("\nNo active worker process.\n");
        return;
    }

    if (kill(childPID, SIGSTOP) == -1)
    {
        perror("Failed to stop worker");
        return;
    }

    printf("\nSIGSTOP sent successfully.\n");

    sleep(1);

    printf("Worker process state: T (Stopped)\n");
}

static void resumeChild(void)
{
    if (!childCreated || !childAlive)
    {
        printf("\nNo active worker process.\n");
        return;
    }

    if (kill(childPID, SIGCONT) == -1)
    {
        perror("Failed to resume worker");
        return;
    }

    printf("\nSIGCONT sent successfully.\n");

    sleep(1);

    char state = getProcessState(childPID);

    if (state == 'R')
        printf("Worker process state: R (Running/Runnable)\n");
    else if (state == 'S')
        printf("Worker process state: S (Sleeping)\n");
    else
        printf("Worker process state: %c\n", state);
}

static void terminateChild(void)
{
    if (!childCreated || !childAlive)
    {
        printf("\nNo active worker process.\n");
        return;
    }

    char state = getProcessState(childPID);

    if (state == '?')
    {
        printf("\nWorker process no longer exists.\n");
        childAlive = 0;
        return;
    }

    if (state == 'T')
    {
        if (kill(childPID, SIGCONT) == -1)
        {
            perror("Failed to resume stopped worker");
            return;
        }
    }

    if (kill(childPID, SIGTERM) == -1)
    {
        perror("Failed to terminate worker");
        return;
    }

    printf("\nSIGTERM sent successfully.\n");

    if (waitpid(childPID, NULL, 0) == -1)
    {
        if (errno != ECHILD)
            perror("waitpid");
    }

    close(parentToChild[1]);
    close(childToParent[0]);

    childAlive = 0;

    printf("Worker process terminated successfully.\n");
    printf("Parent collected the worker using waitpid().\n");
}

static void executeCommand(char *input)
{
    char *args[MAX_ARGS];
    char *token;
    int count = 0;

    token = strtok(input, " ");

    while (token != NULL && count < MAX_ARGS - 1)
    {
        args[count] = token;
        count++;
        token = strtok(NULL, " ");
    }

    args[count] = NULL;

    if (count == 0)
        return;

    pid_t pid = fork();

    if (pid < 0)
    {
        perror("fork failed");
        return;
    }

    if (pid == 0)
    {
        execvp(args[0], args);

        perror("Command execution failed");
        _exit(1);
    }

    if (waitpid(pid, NULL, 0) == -1)
        perror("waitpid");
    else
        printf("\nCommand execution completed.\n");
}

static void showHistory(void)
{
    if (historyCount == 0)
    {
        printf("\nNo commands in history.\n");
        return;
    }

    printf("\nCommand History\n");
    printf("---------------------------------------------\n");

    for (int i = 0; i < historyCount; i++)
        printf("%d. %s\n", i + 1, history[i]);
}

static void cleanup(void)
{
    if (childCreated && childAlive)
    {
        kill(childPID, SIGCONT);
        kill(childPID, SIGTERM);

        waitpid(childPID, NULL, 0);

        close(parentToChild[1]);
        close(childToParent[0]);

        childAlive = 0;
    }
}

void runOSManager(void)
{
    char input[MAX_INPUT];

    printf("\n========================================\n");
    printf("       LINUX PROCESS MANAGEMENT\n");
    printf("========================================\n");
    printf("Type 'help' to see available commands.\n");

    while (1)
    {
        printf("\nosmanager> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL)
            break;

        input[strcspn(input, "\n")] = '\0';

        if (strlen(input) == 0)
            continue;

        addHistory(input);

        if (strcmp(input, "help") == 0)
        {
            printHelp();
        }
        else if (strcmp(input, "create") == 0)
        {
            createChild();
        }
        else if (strcmp(input, "status") == 0)
        {
            showProcessStatus();
        }
        else if (strncmp(input, "message ", 8) == 0)
        {
            sendMessage(input + 8);
        }
        else if (strncmp(input, "task ", 5) == 0)
        {
            sendTask(input + 5);
        }
        else if (strcmp(input, "result") == 0)
        {
            getResult();
        }
        else if (strcmp(input, "stop") == 0)
        {
            stopChild();
        }
        else if (strcmp(input, "resume") == 0)
        {
            resumeChild();
        }
        else if (strcmp(input, "terminate") == 0)
        {
            terminateChild();
        }
        else if (strncmp(input, "execute ", 8) == 0)
        {
            executeCommand(input + 8);
        }
        else if (strcmp(input, "history") == 0)
        {
            showHistory();
        }
        else if (strcmp(input, "clear") == 0)
        {
            printf("\033[2J\033[H");
        }
        else if (strcmp(input, "exit") == 0)
        {
            cleanup();

            printf("\nExiting Linux Process Management System.\n");
            break;
        }
        else
        {
            printf("\nUnknown command: %s\n", input);
            printf("Type 'help' to see available commands.\n");
        }
    }

    cleanup();
}