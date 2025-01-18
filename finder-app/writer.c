#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  openlog("WriterLog", 0, LOG_USER);

  if (argc != 3) {
    syslog(LOG_ERR, "Invalid number of arguments. Expected 2.");
    return EXIT_FAILURE;
  }

  const char *write_file = argv[1];
  const char *write_str = argv[2];

  syslog(LOG_DEBUG, "Writing %s to %s", write_str, write_file);

  FILE *file = fopen(write_file, "w");

  if (file == NULL) {
    syslog(LOG_ERR, "Error opening file %s", write_file);
    return EXIT_FAILURE;
  }

  if (fprintf(file, "%s", write_str) < 0) {
    syslog(LOG_ERR, "Could not create file %s", write_file);
    return EXIT_FAILURE;
  }

  if (fclose(file) != 0) {
    syslog(LOG_ERR, "Could not close file %s", write_file);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
