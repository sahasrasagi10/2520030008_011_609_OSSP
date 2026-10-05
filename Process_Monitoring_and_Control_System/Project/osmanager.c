#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/mman.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>
#include <linux/magic.h>

#include "osmanager.h"

#define INPUT_BUFFER 512
#define MAX_CONTENT 4096
#define MAX_QUEUE 20
#define MAX_PATH 256
#define MAX_RESULT 1024
#define FIFO_PATH "/tmp/ossp_project_fifo"

typedef enum
{
    TASK_CREATE,
    TASK_SEARCH,
    TASK_DELETE
} TaskType;

typedef struct
{
    TaskType type;
    char filename[MAX_PATH];
    char keyword[MAX_PATH];
    char content[MAX_CONTENT];
    int id;
} Task;

typedef struct
{
    Task items[MAX_QUEUE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    sem_t items_available;
} TaskBuffer;

static pid_t worker_pid = -1;
static int worker_created = 0;
static int worker_alive = 0;

static int p2c[2];
static int c2p[2];

static Task queue[MAX_QUEUE];
static int queue_count = 0;
static int next_task_id = 1;

static char last_result[MAX_RESULT];
static int has_result = 0;

static const char *task_name(TaskType t)
{
    if (t == TASK_CREATE)
        return "CREATE FILE";

    if (t == TASK_SEARCH)
        return "SEARCH KEYWORD";

    if (t == TASK_DELETE)
        return "DELETE FILE";

    return "UNKNOWN";
}

static void banner(void)
{
    printf("\n");
    printf("\033[1;36m╔════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║          LINUX PROCESS MANAGEMENT SYSTEM                 ║\033[0m\n");
    printf("\033[1;36m╠════════════════════════════════════════════════════════════╣\033[0m\n");
    printf("\033[1;35m║  Process Manager  │  IPC  │  /proc  │  Signals  │  FCFS ║\033[0m\n");
    printf("\033[1;36m╚════════════════════════════════════════════════════════════╝\033[0m\n");
}

static void help(void)
{
    printf("\n\033[1;33mCOMMANDS\033[0m\n");

    printf("  \033[1;32mcreate\033[0m                         Create worker process\n");
    printf("  \033[1;32mstatus\033[0m                         Show process status\n");
    printf("  \033[1;32mstop / resume / terminate\033[0m      Control worker\n");

    printf("  \033[1;32mcreate-file\033[0m                    Create file and enter contents\n");
    printf("  \033[1;32msearch <file> <keyword>\033[0m        Search for a keyword\n");
    printf("  \033[1;32mdelete-file <file>\033[0m             Delete a file\n");

    printf("  \033[1;32mfile-info <file>\033[0m               Show file information\n");
    printf("  \033[1;32mmemory\033[0m                         Show memory and paging information\n");

    printf("  \033[1;32mqueue / run / result\033[0m            FCFS task handling\n");
    printf("  \033[1;32mexecute <command>\033[0m              Execute a Linux command\n");

    printf("  \033[1;32mclear / help / exit\033[0m\n");
}

static char get_state(pid_t pid)
{
    char path[128];
    char line[256];
    char state = '?';

    FILE *fp;

    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    fp = fopen(path, "r");

    if (!fp)
        return '?';

    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "State:", 6) == 0)
        {
            sscanf(line, "State:%*[^A-Za-z]%c", &state);
            break;
        }
    }

    fclose(fp);

    return state;
}

static void status(void)
{
    char path[128];
    char line[256];

    char name[64] = "?";
    char ppid[32] = "?";
    char threads[32] = "?";
    char vmsize[32] = "?";
    char vmrss[32] = "?";
    char pgid[32] = "?";
    char sid[32] = "?";

    char state = '?';

    FILE *fp;

    if (!worker_created || !worker_alive)
    {
        printf("\n\033[1;31mNo active worker process.\033[0m\n");
        return;
    }

    snprintf(path, sizeof(path), "/proc/%d/status", worker_pid);

    fp = fopen(path, "r");

    if (!fp)
    {
        printf("\n\033[1;31mWorker is no longer available.\033[0m\n");
        worker_alive = 0;
        return;
    }

    while (fgets(line, sizeof(line), fp))
    {
        if (!strncmp(line, "Name:", 5))
            sscanf(line, "Name:%*[^A-Za-z]%63s", name);

        else if (!strncmp(line, "PPid:", 5))
            sscanf(line, "PPid:%*[^0-9]%31s", ppid);

        else if (!strncmp(line, "State:", 6))
            sscanf(line, "State:%*[^A-Za-z]%c", &state);

        else if (!strncmp(line, "Threads:", 8))
            sscanf(line, "Threads:%*[^0-9]%31s", threads);

        else if (!strncmp(line, "VmSize:", 7))
            sscanf(line, "VmSize:%*[^0-9]%31s", vmsize);

        else if (!strncmp(line, "VmRSS:", 6))
            sscanf(line, "VmRSS:%*[^0-9]%31s", vmrss);
    }

    fclose(fp);

    snprintf(pgid, sizeof(pgid), "%d", (int)getpgid(worker_pid));
    snprintf(sid, sizeof(sid), "%d", (int)getsid(worker_pid));

    const char *meaning =
        state == 'R' ? "Running" : state == 'S' ? "Sleeping"
                               : state == 'T'   ? "Stopped"
                               : state == 'Z'   ? "Zombie"
                                                : "Other";

    printf("\n\033[1;36m╔════════════════ PROCESS STATUS ════════════════╗\033[0m\n");

    printf("║ PID       : %-36d ║\n", worker_pid);
    printf("║ PPID      : %-36s ║\n", ppid);
    printf("║ State     : %c (%-29s) ║\n", state, meaning);
    printf("║ Threads   : %-36s ║\n", threads);
    printf("║ PGID      : %-36s ║\n", pgid);
    printf("║ SID       : %-36s ║\n", sid);
    printf("║ VmSize    : %-32s KB ║\n", vmsize);
    printf("║ VmRSS     : %-32s KB ║\n", vmrss);

    printf("╚═══════════════════════════════════════════════╝\033[0m\n");
}

static int write_full(int fd, const void *buf, size_t n)
{
    const char *p = (const char *)buf;

    while (n)
    {
        ssize_t w = write(fd, p, n);

        if (w < 0)
        {
            if (errno == EINTR)
                continue;

            return -1;
        }

        p += w;
        n -= (size_t)w;
    }

    return 0;
}

static int read_full(int fd, void *buf, size_t n)
{
    char *p = (char *)buf;

    while (n)
    {
        ssize_t r = read(fd, p, n);

        if (r == 0)
            return 0;

        if (r < 0)
        {
            if (errno == EINTR)
                continue;

            return -1;
        }

        p += r;
        n -= (size_t)r;
    }

    return 1;
}

static void send_result(const char *s)
{
    (void)write_full(c2p[1], s, strlen(s) + 1);
}

static void worker_create_file(const Task *t)
{
    int fd;
    char r[MAX_RESULT];

    fd = open(
        t->filename,
        O_WRONLY | O_CREAT | O_TRUNC,
        0644);

    if (fd < 0)
    {
        snprintf(
            r,
            sizeof(r),
            "CREATE failed: %s",
            strerror(errno));

        send_result(r);
        return;
    }

    ssize_t n = (ssize_t)strlen(t->content);

    if (write_full(fd, t->content, (size_t)n) < 0)
    {
        snprintf(
            r,
            sizeof(r),
            "CREATE failed while writing '%s'.",
            t->filename);
    }
    else
    {
        snprintf(
            r,
            sizeof(r),
            "CREATE complete | File: %s | Bytes written: %ld",
            t->filename,
            (long)n);
    }

    close(fd);

    send_result(r);
}

static void worker_search(const Task *t)
{
    int fd;

    char data[MAX_CONTENT + 1];
    char buf[1024];
    char r[MAX_RESULT];

    size_t total = 0;

    ssize_t n;
    long count = 0;

    fd = open(t->filename, O_RDONLY);

    if (fd < 0)
    {
        snprintf(
            r,
            sizeof(r),
            "SEARCH failed: %s",
            strerror(errno));

        send_result(r);
        return;
    }

    while ((n = read(fd, buf, sizeof(buf))) > 0 &&
           total < MAX_CONTENT)
    {
        size_t take = (size_t)n;

        if (take > MAX_CONTENT - total)
            take = MAX_CONTENT - total;

        memcpy(data + total, buf, take);

        total += take;
    }

    close(fd);

    data[total] = '\0';

    if (n < 0)
    {
        snprintf(
            r,
            sizeof(r),
            "SEARCH failed while reading '%s'.",
            t->filename);

        send_result(r);
        return;
    }

    if (t->keyword[0])
    {
        char *p = data;
        size_t k = strlen(t->keyword);

        while (k && (p = strstr(p, t->keyword)) != NULL)
        {
            count++;
            p += k;
        }
    }

    snprintf(
        r,
        sizeof(r),
        "SEARCH complete | File: %s | Keyword: %s | Occurrences: %ld",
        t->filename,
        t->keyword,
        count);

    send_result(r);
}

static void worker_delete(const Task *t)
{
    char r[MAX_RESULT];

    if (unlink(t->filename) < 0)
    {
        snprintf(
            r,
            sizeof(r),
            "DELETE failed: %s",
            strerror(errno));
    }
    else
    {
        snprintf(
            r,
            sizeof(r),
            "DELETE complete | File: %s removed successfully.",
            t->filename);
    }

    send_result(r);
}

static void fifo_demo_internal(void)
{
    unlink(FIFO_PATH);

    if (mkfifo(FIFO_PATH, 0600) < 0)
        return;

    pid_t p = fork();

    if (p < 0)
    {
        unlink(FIFO_PATH);
        return;
    }

    if (p == 0)
    {
        int fd = open(FIFO_PATH, O_RDONLY);

        if (fd >= 0)
        {
            char b[64] = {0};

            (void)read(fd, b, sizeof(b) - 1);

            close(fd);
        }

        _exit(0);
    }

    int fd = open(FIFO_PATH, O_WRONLY);

    if (fd >= 0)
    {
        const char *msg = "OSSP FIFO";

        (void)write(fd, msg, strlen(msg) + 1);

        close(fd);
    }

    waitpid(p, NULL, 0);

    unlink(FIFO_PATH);
}

static void *reader_thread(void *arg)
{
    TaskBuffer *tb = (TaskBuffer *)arg;

    while (1)
    {
        Task t;

        int ok = read_full(
            p2c[0],
            &t,
            sizeof(t));

        if (ok <= 0)
            break;

        pthread_mutex_lock(&tb->mutex);

        if (t.id == 0)
        {
            pthread_mutex_unlock(&tb->mutex);
            break;
        }

        if (tb->count < MAX_QUEUE)
        {
            tb->items[tb->tail] = t;

            tb->tail =
                (tb->tail + 1) % MAX_QUEUE;

            tb->count++;

            pthread_cond_signal(
                &tb->not_empty);
        }

        pthread_mutex_unlock(&tb->mutex);

        sem_post(&tb->items_available);
    }

    return NULL;
}

static void execute_task(const Task *t)
{
    if (t->type == TASK_CREATE)
        worker_create_file(t);

    else if (t->type == TASK_SEARCH)
        worker_search(t);

    else if (t->type == TASK_DELETE)
        worker_delete(t);
}

static void *executor_thread(void *arg)
{
    TaskBuffer *tb = (TaskBuffer *)arg;

    while (1)
    {
        sem_wait(&tb->items_available);

        pthread_mutex_lock(&tb->mutex);

        while (tb->count == 0)
        {
            pthread_cond_wait(
                &tb->not_empty,
                &tb->mutex);
        }

        Task t = tb->items[tb->head];

        tb->head =
            (tb->head + 1) % MAX_QUEUE;

        tb->count--;

        pthread_mutex_unlock(&tb->mutex);

        if (t.id == 0)
            break;

        execute_task(&t);
    }

    return NULL;
}

static void *monitor_thread(void *arg)
{
    (void)arg;

    while (1)
    {
        struct timespec ts = {
            0,
            200000000};

        nanosleep(&ts, NULL);

        if (access("/proc/self/status", F_OK) != 0)
            break;

        pthread_testcancel();
    }

    return NULL;
}

static volatile sig_atomic_t worker_stop_requested = 0;

static void worker_sigterm(int sig)
{
    (void)sig;

    worker_stop_requested = 1;
}

static void worker_process(void)
{
    close(p2c[1]);
    close(c2p[0]);

    (void)setpgid(0, 0);

    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = worker_sigterm;

    sigemptyset(&sa.sa_mask);

    sigaction(SIGTERM, &sa, NULL);

    TaskBuffer tb;

    memset(&tb, 0, sizeof(tb));

    pthread_mutex_init(
        &tb.mutex,
        NULL);

    pthread_cond_init(
        &tb.not_empty,
        NULL);

    sem_init(
        &tb.items_available,
        0,
        0);

    pthread_t reader;
    pthread_t executor;
    pthread_t monitor;

    pthread_create(
        &reader,
        NULL,
        reader_thread,
        &tb);

    pthread_create(
        &executor,
        NULL,
        executor_thread,
        &tb);

    pthread_create(
        &monitor,
        NULL,
        monitor_thread,
        NULL);

    while (!worker_stop_requested)
    {
        struct timespec ts = {
            0,
            100000000};

        nanosleep(&ts, NULL);

        pthread_testcancel();
    }

    pthread_cancel(monitor);
    pthread_join(monitor, NULL);

    pthread_cancel(reader);
    pthread_join(reader, NULL);

    pthread_cancel(executor);

    sem_post(&tb.items_available);

    pthread_join(executor, NULL);

    sem_destroy(&tb.items_available);

    pthread_cond_destroy(&tb.not_empty);

    pthread_mutex_destroy(&tb.mutex);

    close(p2c[0]);
    close(c2p[1]);

    _exit(0);
}

static void create_worker(void)
{
    if (worker_created && worker_alive)
    {
        printf(
            "\n\033[1;33mWorker already exists. PID: %d\033[0m\n",
            worker_pid);

        return;
    }

    if (pipe(p2c) < 0 ||
        pipe(c2p) < 0)
    {
        perror("pipe");
        return;
    }

    fifo_demo_internal();

    worker_pid = fork();

    if (worker_pid < 0)
    {
        perror("fork");
        return;
    }

    if (worker_pid == 0)
        worker_process();

    close(p2c[0]);
    close(c2p[1]);

    worker_created = 1;
    worker_alive = 1;

    has_result = 0;
    last_result[0] = '\0';

    printf(
        "\n\033[1;32m✓ WORKER PROCESS CREATED\033[0m\n");

    printf(
        "Parent PID : %d\n"
        "Worker PID : %d\n"
        "IPC        : 2 anonymous pipes\n",
        getpid(),
        worker_pid);
}

static int enqueue(Task t)
{
    if (queue_count >= MAX_QUEUE)
        return 0;

    queue[queue_count++] = t;

    return 1;
}

static Task dequeue_task(void)
{
    Task t = queue[0];

    for (int i = 1; i < queue_count; i++)
        queue[i - 1] = queue[i];

    queue_count--;

    return t;
}

static void show_queue(void)
{
    printf(
        "\n\033[1;33m╔════════════ FCFS TASK QUEUE ════════════╗\033[0m\n");

    if (!queue_count)
    {
        printf(
            "║ Queue is empty.                         ║\n");

        printf(
            "╚═════════════════════════════════════════╝\n");

        return;
    }

    for (int i = 0; i < queue_count; i++)
    {
        printf(
            "║ #%02d  %-18s %-16s ║\n",
            queue[i].id,
            task_name(queue[i].type),
            queue[i].filename);
    }

    printf(
        "╚═════════════════════════════════════════╝\033[0m\n");
}

static void create_file_task(void)
{
    if (!worker_created || !worker_alive)
    {
        printf(
            "\n\033[1;31mCreate the worker first.\033[0m\n");

        return;
    }

    Task t;

    memset(&t, 0, sizeof(t));

    t.type = TASK_CREATE;

    t.id = next_task_id++;

    printf("Enter filename: ");
    fflush(stdout);

    if (!fgets(
            t.filename,
            sizeof(t.filename),
            stdin))
        return;

    t.filename[strcspn(t.filename, "\n")] = 0;

    printf("Enter content: ");
    fflush(stdout);

    if (!fgets(
            t.content,
            sizeof(t.content),
            stdin))
        return;

    t.content[strcspn(t.content, "\n")] = 0;

    if (!enqueue(t))
    {
        printf(
            "\033[1;31mQueue is full.\033[0m\n");

        return;
    }

    printf(
        "\033[1;32m✓ Task #%d added: CREATE FILE\033[0m\n",
        t.id);
}

static void search_task(char *line)
{
    if (!worker_created || !worker_alive)
    {
        printf(
            "\n\033[1;31mCreate the worker first.\033[0m\n");

        return;
    }

    char *a = strtok(line, " ");
    char *file = strtok(NULL, " ");
    char *key = strtok(NULL, " ");

    if (!a || !file || !key)
    {
        printf(
            "Usage: search <file> <keyword>\n");

        return;
    }

    Task t;

    memset(&t, 0, sizeof(t));

    t.type = TASK_SEARCH;

    t.id = next_task_id++;

    strncpy(
        t.filename,
        file,
        MAX_PATH - 1);

    strncpy(
        t.keyword,
        key,
        MAX_PATH - 1);

    if (!enqueue(t))
    {
        printf(
            "\033[1;31mQueue is full.\033[0m\n");

        return;
    }

    printf(
        "\033[1;32m✓ Task #%d added: SEARCH KEYWORD\033[0m\n",
        t.id);
}

static void delete_task(char *line)
{
    if (!worker_created || !worker_alive)
    {
        printf(
            "\n\033[1;31mCreate the worker first.\033[0m\n");

        return;
    }

    char *a = strtok(line, " ");
    char *file = strtok(NULL, " ");

    if (!a || !file)
    {
        printf(
            "Usage: delete-file <file>\n");

        return;
    }

    Task t;

    memset(&t, 0, sizeof(t));

    t.type = TASK_DELETE;

    t.id = next_task_id++;

    strncpy(
        t.filename,
        file,
        MAX_PATH - 1);

    if (!enqueue(t))
    {
        printf(
            "\033[1;31mQueue is full.\033[0m\n");

        return;
    }

    printf(
        "\033[1;32m✓ Task #%d added: DELETE FILE\033[0m\n",
        t.id);
}

static void file_info(char *line)
{
    char *a = strtok(line, " ");
    char *file = strtok(NULL, " ");

    if (!a || !file)
    {
        printf(
            "Usage: file-info <file>\n");

        return;
    }

    struct stat st;

    if (stat(file, &st) < 0)
    {
        printf(
            "\033[1;31m%s\033[0m\n",
            strerror(errno));

        return;
    }

    struct statfs fs;

    const char *fstype = "Unknown";

    if (statfs(file, &fs) == 0)
    {
        if ((unsigned long)fs.f_type ==
            EXT4_SUPER_MAGIC)
        {
            fstype = "ext4";
        }
        else if ((unsigned long)fs.f_type ==
                 TMPFS_MAGIC)
        {
            fstype = "tmpfs";
        }
        else if ((unsigned long)fs.f_type ==
                 OVERLAYFS_SUPER_MAGIC)
        {
            fstype = "overlay";
        }
    }

    char perms[11];

    snprintf(
        perms,
        sizeof(perms),
        "%c%c%c%c%c%c%c%c%c%c",
        S_ISDIR(st.st_mode) ? 'd' : '-',
        st.st_mode & S_IRUSR ? 'r' : '-',
        st.st_mode & S_IWUSR ? 'w' : '-',
        st.st_mode & S_IXUSR ? 'x' : '-',
        st.st_mode & S_IRGRP ? 'r' : '-',
        st.st_mode & S_IWGRP ? 'w' : '-',
        st.st_mode & S_IXGRP ? 'x' : '-',
        st.st_mode & S_IROTH ? 'r' : '-',
        st.st_mode & S_IWOTH ? 'w' : '-',
        st.st_mode & S_IXOTH ? 'x' : '-');

    printf(
        "\n\033[1;36m╔════════════════ FILE INFO ═══════════════════╗\033[0m\n");

    printf(
        "║ File        : %-32s ║\n",
        file);

    printf(
        "║ Inode       : %-32llu ║\n",
        (unsigned long long)st.st_ino);

    printf(
        "║ Size        : %-25lld bytes ║\n",
        (long long)st.st_size);

    printf(
        "║ Permissions : %-32s ║\n",
        perms);

    printf(
        "║ Links       : %-32lu ║\n",
        (unsigned long)st.st_nlink);

    printf(
        "║ Filesystem  : %-32s ║\n",
        fstype);

    printf(
        "╚═════════════════════════════════════════════╝\033[0m\n");

    int fd = open(file, O_RDONLY);

    if (fd >= 0)
    {
        char buf[256];

        (void)read(
            fd,
            buf,
            sizeof(buf));

        close(fd);

        FILE *fp = fopen(file, "r");

        if (fp)
        {
            (void)fread(
                buf,
                1,
                sizeof(buf),
                fp);

            fclose(fp);
        }

        if (st.st_size > 0)
        {
            int mfd = open(
                file,
                O_RDONLY);

            if (mfd >= 0)
            {
                void *p = mmap(
                    NULL,
                    (size_t)st.st_size,
                    PROT_READ,
                    MAP_PRIVATE,
                    mfd,
                    0);

                if (p != MAP_FAILED)
                {
                    munmap(
                        p,
                        (size_t)st.st_size);
                }

                close(mfd);
            }
        }
    }
}

static void memory_info(void)
{
    if (!worker_created || !worker_alive)
    {
        printf(
            "\n\033[1;31mCreate the worker first.\033[0m\n");

        return;
    }

    char path[128];
    char line[256];

    long page = sysconf(_SC_PAGESIZE);

    long minflt = 0;
    long majflt = 0;
    long rss = 0;
    long vpages = 0;

    unsigned long long vbytes = 0;

    long rss_kb = 0;

    snprintf(
        path,
        sizeof(path),
        "/proc/%d/status",
        worker_pid);

    FILE *fp = fopen(path, "r");

    if (fp)
    {
        while (fgets(line, sizeof(line), fp))
        {
            if (!strncmp(line, "VmSize:", 7))
            {
                sscanf(
                    line,
                    "VmSize:%*[^0-9]%llu",
                    &vbytes);
            }
            else if (!strncmp(line, "VmRSS:", 6))
            {
                sscanf(
                    line,
                    "VmRSS:%ld",
                    &rss_kb);
            }
        }

        fclose(fp);
    }

    snprintf(
        path,
        sizeof(path),
        "/proc/%d/statm",
        worker_pid);

    fp = fopen(path, "r");

    if (fp)
    {
        long dummy;

        fscanf(
            fp,
            "%ld %ld",
            &dummy,
            &rss);

        vpages = dummy;

        fclose(fp);
    }

    snprintf(
        path,
        sizeof(path),
        "/proc/%d/stat",
        worker_pid);

    fp = fopen(path, "r");

    if (fp)
    {
        char buf[4096];

        if (fgets(buf, sizeof(buf), fp))
        {
            char *p = strrchr(buf, ')');

            if (p)
            {
                p++;

                int field = 3;

                char *tok = strtok(
                    p,
                    " ");

                while (tok)
                {
                    if (field == 10)
                        minflt =
                            strtol(
                                tok,
                                NULL,
                                10);

                    if (field == 12)
                        majflt =
                            strtol(
                                tok,
                                NULL,
                                10);

                    field++;

                    tok = strtok(
                        NULL,
                        " ");
                }
            }
        }

        fclose(fp);
    }

    printf(
        "\n\033[1;35m╔════════════════ MEMORY MONITOR ══════════════╗\033[0m\n");

    printf(
        "║ PID             : %-29d ║\n",
        worker_pid);

    printf(
        "║ Page Size       : %-24ld bytes ║\n",
        page);

    printf(
        "║ Virtual Memory  : %-25llu KB ║\n",
        vbytes);

    printf(
        "║ Resident Memory : %-25ld KB ║\n",
        rss_kb);

    printf(
        "║ Virtual Pages   : %-29ld ║\n",
        vpages);

    printf(
        "║ Resident Pages  : %-29ld ║\n",
        rss);

    printf(
        "║ Minor Faults    : %-29ld ║\n",
        minflt);

    printf(
        "║ Major Faults    : %-29ld ║\n",
        majflt);

    printf(
        "╚═════════════════════════════════════════════╝\033[0m\n");

    size_t alloc_size =
        (size_t)page * 4;

    char *mem =
        malloc(alloc_size);

    if (mem)
    {
        memset(
            mem,
            1,
            alloc_size);

        free(mem);
    }

    pid_t c = fork();

    if (c == 0)
    {
        char *cow =
            malloc((size_t)page);

        if (cow)
        {
            cow[0] = 'C';
            free(cow);
        }

        _exit(0);
    }

    if (c > 0)
        waitpid(c, NULL, 0);
}

static void run_task(void)
{
    if (!worker_created || !worker_alive)
    {
        printf(
            "\n\033[1;31mCreate the worker first.\033[0m\n");

        return;
    }

    if (!queue_count)
    {
        printf(
            "\n\033[1;33mNo pending tasks.\033[0m\n");

        return;
    }

    if (get_state(worker_pid) == 'T')
    {
        printf(
            "\n\033[1;31mWorker is stopped. Use resume first.\033[0m\n");

        return;
    }

    Task t = dequeue_task();

    if (write_full(
            p2c[1],
            &t,
            sizeof(t)) < 0)
    {
        perror("dispatch");
        return;
    }

    printf(
        "\n\033[1;36mFCFS DISPATCH\033[0m  Task #%d → %s → Worker PID %d\n",
        t.id,
        task_name(t.type),
        worker_pid);

    /*
     * Wait for THIS task's result.
     * This fixes the previous problem where result()
     * could display an older task's result.
     */

    char buffer[MAX_RESULT];

    ssize_t n = read(
        c2p[0],
        buffer,
        sizeof(buffer) - 1);

    if (n > 0)
    {
        buffer[n] = '\0';

        strncpy(
            last_result,
            buffer,
            MAX_RESULT - 1);

        last_result[MAX_RESULT - 1] = '\0';

        has_result = 1;

        printf(
            "\033[1;32m✓ TASK COMPLETED\033[0m\n");

        printf(
            "%s\n",
            last_result);
    }
    else
    {
        printf(
            "\033[1;31m✗ No result received from worker.\033[0m\n");
    }
}

static void result(void)
{
    if (has_result)
    {
        printf(
            "\n\033[1;32m✓ RESULT\033[0m\n");

        printf(
            "%s\n",
            last_result);
    }
    else
    {
        printf(
            "\n\033[1;33mNo result available.\033[0m\n");
    }
}

static void control(
    int sig,
    const char *name)
{
    if (!worker_created || !worker_alive)
    {
        printf(
            "\n\033[1;31mNo active worker.\033[0m\n");

        return;
    }

    if (kill(worker_pid, sig) < 0)
    {
        perror(name);
        return;
    }

    printf(
        "\n\033[1;33m%s sent to PID %d.\033[0m\n",
        name,
        worker_pid);
}

static void terminate_worker(void)
{
    if (!worker_created || !worker_alive)
    {
        printf(
            "\n\033[1;31mNo active worker.\033[0m\n");

        return;
    }

    if (get_state(worker_pid) == 'T')
        kill(worker_pid, SIGCONT);

    if (kill(worker_pid, SIGTERM) < 0)
    {
        perror("SIGTERM");
        return;
    }

    waitpid(
        worker_pid,
        NULL,
        0);

    close(p2c[1]);
    close(c2p[0]);

    worker_alive = 0;
    worker_created = 0;

    has_result = 0;
    last_result[0] = '\0';

    printf(
        "\n\033[1;32m✓ Worker terminated and collected.\033[0m\n");
}

static void execute_command(char *cmd)
{
    char *args[20];

    int n = 0;

    char *p = strtok(
        cmd,
        " ");

    while (p && n < 19)
    {
        args[n++] = p;

        p = strtok(
            NULL,
            " ");
    }

    args[n] = NULL;

    if (!n)
        return;

    pid_t pid = fork();

    if (pid < 0)
    {
        perror("fork");
        return;
    }

    if (pid == 0)
    {
        execvp(
            args[0],
            args);

        perror("execvp");

        _exit(1);
    }

    waitpid(
        pid,
        NULL,
        0);

    printf(
        "\n\033[1;32m✓ Command completed.\033[0m\n");
}

static void cleanup(void)
{
    if (worker_created && worker_alive)
    {
        kill(
            worker_pid,
            SIGCONT);

        kill(
            worker_pid,
            SIGTERM);

        waitpid(
            worker_pid,
            NULL,
            0);

        close(p2c[1]);
        close(c2p[0]);

        worker_alive = 0;
        worker_created = 0;
    }
}

void runOSManager(void)
{
    char input[INPUT_BUFFER];

    banner();

    printf(
        "\nType \033[1;33mhelp\033[0m to view commands.\n");

    while (1)
    {
        printf(
            "\n\033[1;36mossp>\033[0m ");

        fflush(stdout);

        if (!fgets(
                input,
                sizeof(input),
                stdin))
            break;

        input[strcspn(input, "\n")] = 0;

        if (!input[0])
            continue;

        if (!strcmp(input, "help"))
        {
            help();
        }

        else if (!strcmp(input, "create"))
        {
            create_worker();
        }

        else if (!strcmp(input, "status"))
        {
            status();
        }

        else if (!strcmp(input, "create-file"))
        {
            create_file_task();
        }

        else if (!strncmp(input, "search ", 7))
        {
            search_task(input);
        }

        else if (!strncmp(input, "delete-file ", 12))
        {
            delete_task(input);
        }

        else if (!strncmp(input, "file-info ", 10))
        {
            file_info(input);
        }

        else if (!strcmp(input, "memory"))
        {
            memory_info();
        }

        else if (!strcmp(input, "queue"))
        {
            show_queue();
        }

        else if (!strcmp(input, "run"))
        {
            run_task();
        }

        else if (!strcmp(input, "result"))
        {
            result();
        }

        else if (!strcmp(input, "stop"))
        {
            control(
                SIGSTOP,
                "SIGSTOP");
        }

        else if (!strcmp(input, "resume"))
        {
            control(
                SIGCONT,
                "SIGCONT");
        }

        else if (!strcmp(input, "terminate"))
        {
            terminate_worker();
        }

        else if (!strncmp(input, "execute ", 8))
        {
            execute_command(
                input + 8);
        }

        else if (!strcmp(input, "clear"))
        {
            printf(
                "\033[2J\033[H");

            banner();
        }

        else if (!strcmp(input, "exit"))
        {
            cleanup();

            printf(
                "\n\033[1;36mExiting Linux Process Management System.\033[0m\n");

            break;
        }

        else
        {
            printf(
                "\n\033[1;31mUnknown command. Type help.\033[0m\n");
        }
    }

    cleanup();
}
