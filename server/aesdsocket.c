#include "../aesd-char-driver/aesd_ioctl.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define PORT "9000"
#define IP_ADDR_LEN 40
#define MAX_PACKET_SIZE 1500
#define IOCTL_CMD "AESDCHAR_IOCSEEKTO"

#if (USE_AESD_CHAR_DEVICE == 1)
#define FILE_PATH "/dev/aesdchar"
#else
#define FILE_PATH "/var/tmp/aesdsocketdata"
#endif

struct conn_t {
  pthread_t thread_id;
  int fd;
  char ip_addr[IP_ADDR_LEN];
  pthread_mutex_t *mutex_ptr;
  int finished;
  int return_val;
};

struct node_t {
  struct conn_t *thread;
  struct node_t *next;
};

static void signal_handler(int signal_number);
void *sock_thread(void *thread);
void join_threads(struct node_t **head);
static void timer_thread(union sigval sigval);
bool start_timer(pthread_mutex_t *mutex);

bool caught_signal = false;

static void signal_handler(int signal_number) {
  switch (signal_number) {
  case SIGINT:
  case SIGTERM:
    caught_signal = true;
    syslog(LOG_INFO, "Caught signal %s, exiting", strsignal(signal_number));
    break;
  }
}

void daemonize() {
  int pid = fork();
  if (pid == 0) {
    setsid();
    int chdir_ret = chdir("/");
    if (chdir_ret) {
      perror("chdir");
    }
    int fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
      perror("could not open /dev/null for I/O redirection");
      exit(-1);
    }
    if (dup2(fd, STDIN_FILENO) == -1) {
      perror("Could not redirect STDOUT to /dev/null");
    }
    if (dup2(fd, STDOUT_FILENO) == -1) {
      perror("Could not redirect STDOUT to /dev/null");
    }
    if (dup2(fd, STDERR_FILENO) == -1) {
      perror("Could not redirect STDERR to /dev/null");
    }
  } else {
    exit(0);
  }
}

int main(int argc, char **argv) {
  int ret = 0;
  pthread_mutex_t mutex;

  if (pthread_mutex_init(&mutex, NULL)) {
    perror("pthread_mutex_init");
    exit(-1);
  }

  int is_daemon = 0;
#if (USE_AESD_CHAR_DEVICE == 0)
  bool timer_running = false;
#endif
  pthread_attr_t thread_attr;
  struct node_t *head = NULL;
  struct sigaction socket_sigaction;
  memset(&socket_sigaction, 0, sizeof(struct sigaction));
  socket_sigaction.sa_handler = signal_handler;
  if (sigaction(SIGTERM, &socket_sigaction, NULL) != 0) {
    perror("Could not register SIGTERM handler");
  }
  if (sigaction(SIGINT, &socket_sigaction, NULL) != 0) {
    perror("Could not register SIGINT handler");
  }

  if (argc == 2) {
    if (strcmp(argv[1], "-d") == 0) {
      is_daemon = 1;
    } else {
      printf("%s: Invalid argument\n", argv[0]);
      exit(0);
    }
  }
  if (argc > 2) {
    printf("%s: Too many arguments\n", argv[0]);
    exit(0);
  }

  openlog(NULL, 0, (is_daemon) ? LOG_DAEMON : LOG_USER);

  struct addrinfo *res;
  struct addrinfo hints = {
      .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_flags = AI_PASSIVE};

  if (res == NULL || getaddrinfo(NULL, PORT, &hints, &res) != 0) {
    perror("getaddrinfo");
    ret = -1;
    goto exit;
  }

  int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sock < 0) {
    perror("socket");
    ret = -1;
    goto exit;
  }

  int opt_value = 1;
  socklen_t opt_len = sizeof(opt_value);
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_value, opt_len)) {
    perror("setsockopt");
    ret = -1;
    goto exit;
  }

  if (bind(sock, res->ai_addr, res->ai_addrlen)) {
    perror("bind");
    ret = -1;
    goto exit;
  }

  freeaddrinfo(res);

  if (is_daemon) {
    daemonize();
  }

  do {
    ret = listen(sock, 1);
    if (ret) {
      perror("listen");
      ret = -1;
      goto exit;
    }

    struct sockaddr client_addr;
    socklen_t addr_size = sizeof(client_addr);
    int client_fd = accept(sock, &client_addr, &addr_size);
    if (client_fd == -1) {
      perror("accept");
      ret = -1;
      goto exit;
    }

#if (USE_AESD_CHAR_DEVICE == 0)
    if (!timer_running) {
      if (!start_timer(&mutex)) {
        perror("start_timer");
      } else {
        timer_running = true;
      }
    }
#endif

    struct sockaddr_in *sockaddr_in = (struct sockaddr_in *)&client_addr;
    char ip_addr[IP_ADDR_LEN];
    if (inet_ntop(sockaddr_in->sin_family, &(sockaddr_in->sin_addr),
                  (char *)(&ip_addr), (socklen_t)IP_ADDR_LEN) == NULL) {
      perror("Could not get IP address of client");
      ret = -1;
      goto exit;
    };
    syslog(LOG_INFO, "Accepted connection from %s", ip_addr);

    struct conn_t *conn = malloc(sizeof(struct conn_t));
    if (!conn) {
      perror("Could not allocate memory for new connection data");
      ret = -1;
      goto exit;
    }
    conn->fd = client_fd;
    conn->mutex_ptr = &mutex;
    memcpy(conn->ip_addr, ip_addr, sizeof(conn->ip_addr));
    conn->finished = 0;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);

    int rc =
        pthread_create(&(conn->thread_id), &thread_attr, sock_thread, conn);
    if (rc) {
      perror("Could not create thread:");
      ret = -1;
      goto exit;
    } else {
      struct node_t *node = malloc(sizeof(struct node_t));
      node->thread = conn;
      node->next = NULL;
      struct node_t *this_node = head;
      if (this_node == NULL) {
        head = node;
      } else {
        while (this_node->next != NULL) {
          this_node = this_node->next;
        }
        this_node->next = node;
      }

      join_threads(&head);
    }
  } while (!caught_signal);

exit:
  if (sock >= 0) {
    if (close(sock)) {
      perror("Could not close file descriptor for socket");
    }
  }
#if (USE_AESD_CHAR_DEVICE == 0)
  if (!access(FILE_PATH, F_OK)) {
    if (remove(FILE_PATH)) {
      perror("Could not delete out file");
    }
  }
#endif
  join_threads(&head);
  return ret;
}

void *sock_thread(void *thread) {
  struct conn_t *data = (struct conn_t *)thread;

  char *packet_buf = malloc(MAX_PACKET_SIZE * sizeof(char));
  if (!packet_buf) {
    perror("Could not allocate buffer for incoming data");
    data->return_val = -1;
    data->finished = 1;
    return thread;
  }

  int num_bytes_recv = 0;
  int total_bytes_recv = 0;
  int num_reallocs = 0;
  do {
    num_bytes_recv = recv(data->fd, packet_buf + total_bytes_recv,
                          MAX_PACKET_SIZE, MSG_DONTWAIT);
    if (num_bytes_recv == 0) {
      syslog(LOG_INFO, "Closed connection from %s", data->ip_addr);
      break;
    } else if (num_bytes_recv < 0) {
      continue;
    } else {
      int write_rc = -1;
      total_bytes_recv += num_bytes_recv;
      if (*(packet_buf + total_bytes_recv - 1) == '\n') {
        int dont_seek = 0;
        int output_fd =
            open(FILE_PATH, O_CREAT | O_RDWR | O_APPEND,
                 S_IRGRP | S_IRUSR | S_IROTH | S_IWGRP | S_IWUSR | S_IWOTH);
        if (output_fd < 0) {
          perror("Could not create output file");
          data->return_val = -1;
          free(packet_buf);
          data->finished = 1;
          return thread;
        }
        pthread_mutex_lock(data->mutex_ptr);
#if (USE_AESD_CHAR_DEVICE == 1)
        if (!strncmp(packet_buf, IOCTL_CMD, strlen(IOCTL_CMD))) {
          if (strtok(packet_buf, ":,")) {
            struct aesd_seekto seekto;
            char *temp = strtok(NULL, ":,");
            if (temp) {
              seekto.write_cmd = atoi(temp);
            }
            temp = strtok(NULL, ":,");
            if (temp) {
              seekto.write_cmd_offset = atoi(temp);
            }
            write_rc = ioctl(output_fd, AESDCHAR_IOCSEEKTO, &seekto);
            dont_seek = 1;
          }
        } else {
          write_rc = write(output_fd, packet_buf, total_bytes_recv);
        }
#else
        write_rc = write(output_fd, packet_buf, total_bytes_recv);
#endif
        pthread_mutex_unlock(data->mutex_ptr);

        free(packet_buf);
        if (write_rc < 0) {
          perror("Failed to write to output");
          data->return_val = -1;
          close(output_fd);
          data->finished = 1;
          return thread;
        }

        num_reallocs = 0;
        total_bytes_recv = 0;

        if (!dont_seek) {
          lseek(output_fd, 0, SEEK_SET);
        }
        size_t num_bytes_read;
        char *read_buf = malloc(MAX_PACKET_SIZE * sizeof(char));
        if (!read_buf) {
          perror("Could not allocate file read buffer");
          close(output_fd);
          data->return_val = -1;
          data->finished = 1;
          return thread;
        }
        do {
          num_bytes_read = read(output_fd, read_buf, MAX_PACKET_SIZE);
          if (send(data->fd, read_buf, num_bytes_read, 0) == -1) {
            perror("send failed");
            data->return_val = -1;
            free(read_buf);
            close(output_fd);
            data->finished = 1;
            return thread;
          }
        } while (num_bytes_read > 0);

        close(output_fd);
        free(read_buf);

        packet_buf = malloc(MAX_PACKET_SIZE * sizeof(char));

        if (!packet_buf) {
          perror("Could not re-create packet buffer after free");
          free(read_buf);
          data->return_val = -1;
          data->finished = 1;
          return thread;
        }
      } else {
        char *new_ptr = realloc(
            packet_buf, 2 * MAX_PACKET_SIZE + (num_reallocs * MAX_PACKET_SIZE));
        if (!new_ptr) {
          perror("Could not allocate additional memory for incoming data");
          total_bytes_recv = 0;
        } else {
          packet_buf = new_ptr;
          num_reallocs++;
        }
      }
    }
  } while (!caught_signal);

  free(packet_buf);
  data->finished = 1;
  data->return_val = 0;
  return thread;
}

void join_threads(struct node_t **head) {
  struct node_t *node = *head;
  int joined;

  if (node == NULL) {
    return;
  }

  do {
    joined = 0;
    if (node && node->thread->finished) {
      *head = node->next;
      joined = 1;
      void **thread_return_value = NULL;
      pthread_join(node->thread->thread_id, thread_return_value);
      free(node->thread);
      free(node);
      node = *head;
    }
  } while (joined);

  while (node && node->next != NULL) {
    if (node->next->thread->finished) {
      struct node_t *node_to_free = node->next;
      node->next = node->next->next;
      void **thread_return_value = NULL;
      pthread_join(node_to_free->thread->thread_id, thread_return_value);
      free(node_to_free->thread);
      free(node_to_free);
    }
    node = node->next;
  }
}

static void timer_thread(union sigval sigval) {
  pthread_mutex_t *mutex = (pthread_mutex_t *)sigval.sival_ptr;
  int output_fd =
      open(FILE_PATH, O_CREAT | O_RDWR | O_APPEND,
           S_IRGRP | S_IRUSR | S_IROTH | S_IWGRP | S_IWUSR | S_IWOTH);
  if (output_fd < 0) {
    perror("Could not create output file for timestamp");
  } else {
    time_t time_t_time;
    time(&time_t_time);
    struct tm tm_time;
    localtime_r(&time_t_time, &tm_time);
    char buf[256];

    memset(buf, 0, sizeof(buf));
    strftime(buf, sizeof(buf), "timestamp:%a, %d %b %Y %T %z\n", &tm_time);

    pthread_mutex_lock(mutex);
    int write_rc = write(output_fd, buf, sizeof(buf));
    pthread_mutex_unlock(mutex);

    if (write_rc == -1) {
      perror("Could not write timestamp to file");
    }
    close(output_fd);
  }
}

bool start_timer(pthread_mutex_t *mutex) {
  struct sigevent sev = {.sigev_notify = SIGEV_THREAD,
                         .sigev_value.sival_ptr = mutex,
                         .sigev_notify_function = timer_thread};
  timer_t id;
  struct itimerspec spec = {.it_interval = {.tv_sec = 10, .tv_nsec = 0}};
  struct timespec start;
  if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
    printf("Error getting monotonic time");
    return false;
  }
  start.tv_sec += 10;
  if (start.tv_sec < 0) {
    start.tv_nsec += 1000000000L;
    start.tv_sec++;
  }
  spec.it_value = start;
  if (timer_create(CLOCK_MONOTONIC, &sev, &id) != 0) {
    printf("Error creating timer");
    return false;
  }
  if (timer_settime(id, TIMER_ABSTIME, &spec, NULL) != 0) {
    printf("Error setting timer");
    return false;
  }
  return true;
}
