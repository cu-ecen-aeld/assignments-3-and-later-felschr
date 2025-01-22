#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 9000
#define BUFFER_SIZE 1024
#define FILE_PATH "/var/tmp/aesdsocketdata"

int running = 1;

void signal_handler(int signum) {
    syslog(LOG_INFO, "Caught signal, exiting");
    running = 0;
}

int main() {
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
