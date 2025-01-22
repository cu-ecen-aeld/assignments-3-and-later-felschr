#include <signal.h>
#include <stdio.h>
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

void signal_handler() {
    syslog(LOG_INFO, "Caught signal, exiting");
    running = 0;
}

int main(int argc, char *argv[]) {
  int daemon_mode = 0;
  for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "-d") == 0) {
          daemon_mode = 1;
      }
  }

  if (daemon_mode) {
      pid_t pid = fork();
      if (pid < 0) {
          syslog(LOG_ERR, "Fork failed");
          return 1;
      }
      if (pid > 0) {
        return 1;
      }
      umask(0);
      if (chdir("/") < 0) {
          syslog(LOG_ERR, "Chdir failed");
          return 1;
      }
      close(STDIN_FILENO);
      close(STDOUT_FILENO);
      close(STDERR_FILENO);
  }

  if (signal(SIGINT, signal_handler) == SIG_ERR) {
      syslog(LOG_ERR, "Failed to set SIGINT handler");
      return 1;
  }
  if (signal(SIGTERM, signal_handler) == SIG_ERR) {
      syslog(LOG_ERR, "Failed to set SIGTERM handler");
      return 1;
  }

  int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET; 
  serv_addr.sin_port  = htons(PORT);
  serv_addr.sin_addr.s_addr = INADDR_ANY; 

  socklen_t addr_len = sizeof(serv_addr);

  if (bind(sock_fd, (struct sockaddr *) &serv_addr, addr_len) != 0) {
    perror("bind");
    return 1;
  }

  if (listen(sock_fd, 1) != 0) {
    perror("listen");
    return 1;
  }

  char buffer[BUFFER_SIZE];

  while (running) {
    int client_fd = accept(sock_fd, (struct sockaddr *) &serv_addr, &addr_len);
    if (client_fd < 0) {
      perror("accept");
      return 1;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &serv_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);

    FILE *file = fopen(FILE_PATH, "a");
    if (file == NULL) {
        perror("fopen");
        close(client_fd);
        continue;
    }

    while (1) {
        int bytes_received = recv(client_fd, buffer, BUFFER_SIZE, 0);
        if (bytes_received < 0) {
            perror("recv");
            break;
        } else if (bytes_received == 0) {
            break;
        }

        fwrite(buffer, 1, bytes_received, file);
    }

    fclose(file);
    close(client_fd);
    syslog(LOG_INFO, "Closed connection from %s", client_ip);
  }

  close(sock_fd);
  unlink(FILE_PATH);
  return 0;
}
