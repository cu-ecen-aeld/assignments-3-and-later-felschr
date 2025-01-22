#include "fcntl.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>

#define PORT 9000
#define BUFFER_SIZE 1024
#define FILE_PATH "/var/tmp/aesdsocketdata"

int running = 1;
int sock_fd = -1;
int client_fd = -1;
int file_fd = -1;

void signal_handler(int signum __attribute__((unused))) {
    if (signum == SIGINT || signum == SIGTERM) {
        syslog(LOG_INFO, "Caught signal, exiting.");

        if (sock_fd >= 0) close(sock_fd);
        if (client_fd >= 0) close(client_fd);
        if (file_fd >= 0) close(file_fd);
        unlink(FILE_PATH);
        closelog();

        exit(0);
    }
}

int main(int argc, char *argv[]) {
  int daemon_mode = 0;
  for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "-d") == 0) {
          daemon_mode = 1;
      }
  }

  openlog("aesdsocket", LOG_PID, LOG_DAEMON);

  if (signal(SIGINT, signal_handler) == SIG_ERR) {
      syslog(LOG_ERR, "Failed to set SIGINT handler");
      return 1;
  }
  if (signal(SIGTERM, signal_handler) == SIG_ERR) {
      syslog(LOG_ERR, "Failed to set SIGTERM handler");
      return 1;
  }

  sock_fd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET; 
  serv_addr.sin_port  = htons(PORT);
  serv_addr.sin_addr.s_addr = INADDR_ANY; 

  if (bind(sock_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
    perror("bind");
    close(sock_fd);
    return 1;
  }

  if (daemon_mode) {
      pid_t pid = fork();
      if (pid < 0) {
          syslog(LOG_ERR, "Fork failed");
          return 1;
      }
      if (pid > 0) {
        return 0;
      }
      if (setsid() < 0) {
        perror("setsid");
        return 1;
      }
      close(STDIN_FILENO);
      close(STDOUT_FILENO);
      close(STDERR_FILENO);
      open("/dev/null", O_RDONLY);
      open("/dev/null", O_WRONLY);
      open("/dev/null", O_RDWR);
  }

  if (listen(sock_fd, 1) != 0) {
    perror("listen");
    close(sock_fd);
    return 1;
  }

  char buffer[BUFFER_SIZE];

  file_fd = open(FILE_PATH, O_CREAT | O_RDWR | O_APPEND, 0644);
  if (file_fd < 0) {
    perror("open");
    close(sock_fd);
    return 1;
  }

  while (running) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    client_fd = accept(sock_fd, (struct sockaddr *) &client_addr, &addr_len);
    if (client_fd < 0) {
      perror("accept");
      continue;
    }

    char *client_ip = inet_ntoa(client_addr.sin_addr);
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);

    while (1) {
      int bytes_received = recv(client_fd, buffer, BUFFER_SIZE, 0);
      if (bytes_received < 0) {
        perror("recv");
        break;
      } else if (bytes_received == 0) {
        break;
      }

      if (write(file_fd, buffer, bytes_received) < 0) {
        perror("write");
        break;
      }

      if (strchr(buffer, '\n') != NULL) {
        lseek(file_fd, 0, SEEK_SET);
        while ((bytes_received = read(file_fd, buffer, BUFFER_SIZE)) > 0) {
          send(client_fd, buffer, bytes_received, 0);
        }
      }
    }

    close(client_fd);
    client_fd = -1;
    syslog(LOG_INFO, "Closed connection from %s", client_ip);
  }

  close(sock_fd);
  close(file_fd);
  unlink(FILE_PATH);
  closelog();

  return 0;
}
