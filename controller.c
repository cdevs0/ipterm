#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif
typedef SOCKET socket_t;
#define INVALID_SOCKET_VALUE INVALID_SOCKET
static void close_socket(socket_t s) { closesocket(s); }
static int network_init(void) {
  WSADATA wsa;
  return WSAStartup(MAKEWORD(2, 2), &wsa);
}
static void network_cleanup(void) { WSACleanup(); }
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET_VALUE (-1)
static void close_socket(socket_t s) { close(s); }
static int network_init(void) { return 0; }
static void network_cleanup(void) {}
#endif
static int parse_port(const char *text, unsigned short *port) {
  char *end;
  unsigned long value;
  if (text == NULL || *text == '\0')
    return -1;
  value = strtoul(text, &end, 10);
  if (*end != '\0' || value == 0 || value > 65535)
    return -1;
  *port = (unsigned short)value;
  return 0;
}
static int valid_ipv4(const char *address) {
  struct in_addr addr;
  if (address == NULL)
    return 0;
  return inet_pton(AF_INET, address, &addr) == 1;
}
static socket_t connect_receiver(const char *address, unsigned short port) {
  socket_t s;
  struct sockaddr_in addr;
  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET_VALUE)
    return INVALID_SOCKET_VALUE;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, address, &addr.sin_addr) != 1) {
    close_socket(s);
    return INVALID_SOCKET_VALUE;
  }
  if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
#ifdef _WIN32
    fprintf(stderr, "connect() failed: WSA error %d\n", WSAGetLastError());
#else
    perror("connect");
#endif
    close_socket(s);
    return INVALID_SOCKET_VALUE;
  }
  return s;
}
static int authenticate(socket_t fd) {
  struct frame f;
  static const char secret[] = "IPTENC!";
  if (send_frame(fd, MSG_HELLO, 1, secret, sizeof(secret) - 1) != 0) {
    return -1;
  }
  if (recv_frame(fd, &f) != 0)
    return -1;
  if (f.type != MSG_HELLO_OK)
    return -1;
  return 0;
}
static void print_result(const struct frame *f) {
  uint32_t status;
  size_t output_length;
  if (f->length < 4) {
    puts("invalid result");
    return;
  }
  status = ((uint32_t)f->payload[0] << 24) | ((uint32_t)f->payload[1] << 16) |
           ((uint32_t)f->payload[2] << 8) | ((uint32_t)f->payload[3]);
  output_length = f->length - 4;
  printf("exit code: %u\n", status);
  if (output_length != 0) {
    fwrite(f->payload + 4, 1, output_length, stdout);
    if (f->payload[f->length - 1] != '\n')
      putchar('\n');
  }
}
static int send_run(socket_t fd, uint32_t request_id, const char *line) {
  const char *command;
  size_t length;
  if (strncmp(line, "run", 3) != 0)
    return -1;
  command = line + 3;
  while (*command == ' ')
    ++command;
  if (*command == '\0')
    return -1;
  length = strlen(command);
  if (length > MAX_PAYLOAD)
    return -1;
  return send_frame(fd, MSG_RUN, request_id, command, (uint32_t)length);
}
static int receive_response(socket_t fd, uint32_t request_id) {
  struct frame response;
  if (recv_frame(fd, &response) != 0) {
    puts("receiver disconnected");
    return -1;
  }
  if (response.request_id != request_id) {
    puts("protocol error: request ID mismatch");
    return -1;
  }
  switch (response.type) {
  case MSG_RESULT:
    print_result(&response);
    return 0;
  case MSG_ERROR:
    printf("receiver: %.*s\n", (int)response.length,
           (const char *)response.payload);
    return 0;
  default:
    puts("protocol error");
    return -1;
  }
}
static int execute_run(socket_t fd, uint32_t *request_id, const char *command) {
  char line[MAX_PAYLOAD];
  if (command == NULL || *command == '\0') {
    puts("usage: run <command>");
    return 0;
  }
  if (snprintf(line, sizeof(line), "run %s", command) >= (int)sizeof(line)) {
    puts("command too long");
    return 0;
  }
  if (send_run(fd, *request_id, line) != 0) {
    puts("invalid run command");
    return 0;
  }
  if (receive_response(fd, *request_id) != 0)
    return -1;
  ++(*request_id);
  return 0;
}
static int process_select(const char *line, char *ip, size_t ip_size,
                          unsigned short *port) {
  char argument[128];
  const char *p;
  if (strncmp(line, "select", 6) != 0)
    return -1;
  p = line + 6;
  while (*p == ' ')
    ++p;
  if (strncmp(p, "ip", 2) == 0 && (p[2] == ' ' || p[2] == '\0')) {
    p += 2;
    while (*p == ' ')
      ++p;
    if (*p == '\0') {
      puts("usage: select ip <IPv4 address>");
      return 0;
    }
    if (sscanf(p, "%127s", argument) != 1) {
      puts("usage: select ip <IPv4 address>");
      return 0;
    }
    if (!valid_ipv4(argument)) {
      printf("invalid IPv4 address: %s\n", argument);
      return 0;
    }
    if (strlen(argument) >= ip_size) {
      puts("IP address too long");
      return 0;
    }
    strcpy(ip, argument);
    printf("selected IP: %s\n", ip);
    return 0;
  }
  if (strncmp(p, "port", 4) == 0 && (p[4] == ' ' || p[4] == '\0')) {
    p += 4;
    while (*p == ' ')
      ++p;
    if (*p == '\0') {
      puts("usage: select port <port>");
      return 0;
    }
    if (sscanf(p, "%127s", argument) != 1) {
      puts("usage: select port <port>");
      return 0;
    }
    if (parse_port(argument, port) != 0) {
      puts("invalid port");
      return 0;
    }
    printf("selected port: %u\n", (unsigned)*port);
    return 0;
  }
  puts("usage:");
  puts("  select ip <IPv4 address>");
  puts("  select port <port>");
  return 0;
}
static int process_command(socket_t fd, uint32_t *request_id, char *ip,
                           size_t ip_size, unsigned short *port,
                           const char *line) {
  char command[MAX_PAYLOAD];
  if (line == NULL || *line == '\0')
    return 0;
  if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
    return 1;
  }
  if (strncmp(line, "select", 6) == 0 && (line[6] == ' ' || line[6] == '\0')) {
    return process_select(line, ip, ip_size, port);
  }
  if (strncmp(line, "run", 3) == 0 && (line[3] == ' ' || line[3] == '\0')) {
    const char *remote_command = line + 3;
    while (*remote_command == ' ')
      ++remote_command;
    if (*remote_command == '\0') {
      puts("usage: run <command>");
      return 0;
    }
    if (execute_run(fd, request_id, remote_command) != 0) {
      return -1;
    }
    return 0;
  }
  if (strlen(line) >= sizeof(command)) {
    puts("command too long");
    return 0;
  }
  strcpy(command, line);
  if (execute_run(fd, request_id, command) != 0) {
    return -1;
  }
  return 0;
}
int main(int argc, char **argv) {
  socket_t fd;
  char ip[INET_ADDRSTRLEN] = "";
  unsigned short port = 9000;
  uint32_t request_id = 2;
  int command_mode = 0;
  const char *command = NULL;
  int i;
  if (argc == 1) {
    fprintf(stderr,
            "usage:\n"
            "  %s <receiver-ip> [port]\n"
            "  %s -c <command> <receiver-ip> [port]\n"
            "  %s -h\n",
            argv[0], argv[0], argv[0]);
    return 1;
  }
  for (i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      puts("ipterm controller");
      puts("");
      puts("Usage:");
      printf("  %s <receiver-ip> [port]\n", argv[0]);
      printf("  %s -c <command> <receiver-ip> [port]\n", argv[0]);
      puts("");
      puts("Commands:");
      puts("  run <command>");
      puts("  select ip <IPv4>");
      puts("  select port <port>");
      puts("  quit");
      puts("");
      puts("Examples:");
      printf("  %s 192.168.100.13 9000\n", argv[0]);
      printf("  %s -c \"hostname\" 192.168.100.13 9000\n", argv[0]);
      printf("  %s -c \"run hostname\" 192.168.100.13 9000\n", argv[0]);
      printf("  %s -c \"select ip 192.168.100.13\" "
             "192.168.100.13 9000\n",
             argv[0]);
      return 0;
    }
    if (strcmp(argv[i], "-c") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "-c requires a command\n");
        return 1;
      }
      command_mode = 1;
      command = argv[++i];
      continue;
    }
    if (ip[0] == '\0') {
      if (!valid_ipv4(argv[i])) {
        fprintf(stderr, "invalid receiver IP: %s\n", argv[i]);
        return 1;
      }
      if (strlen(argv[i]) >= sizeof(ip)) {
        fprintf(stderr, "IP address too long\n");
        return 1;
      }
      strcpy(ip, argv[i]);
      continue;
    }
    if (port == 9000) {
      if (parse_port(argv[i], &port) != 0) {
        fprintf(stderr, "invalid port: %s\n", argv[i]);
        return 1;
      }
      continue;
    }
    fprintf(stderr, "unexpected argument: %s\n", argv[i]);
    return 1;
  }
  if (ip[0] == '\0') {
    fprintf(stderr, "receiver IP not specified\n");
    return 1;
  }
  if (network_init() != 0) {
    fprintf(stderr, "network initialization failed\n");
    return 1;
  }
  fd = connect_receiver(ip, port);
  if (fd == INVALID_SOCKET_VALUE) {
    fprintf(stderr, "cannot connect to receiver\n");
    network_cleanup();
    return 1;
  }
  if (authenticate(fd) != 0) {
    fprintf(stderr, "authentication failed\n");
    close_socket(fd);
    network_cleanup();
    return 1;
  }
  puts("Connected to receiver.");
  if (command_mode) {
    int result;
    result = process_command(fd, &request_id, ip, sizeof(ip), &port, command);
    close_socket(fd);
    network_cleanup();
    if (result < 0)
      return 1;
    return 0;
  }
  puts("");
  puts("Commands:");
  puts("  run <command>");
  puts("  select ip <IPv4>");
  puts("  select port <port>");
  puts("  quit");
  puts("");
  for (;;) {
    char line[MAX_PAYLOAD];
    int result;
    fputs("controller> ", stdout);
    fflush(stdout);
    if (fgets(line, sizeof(line), stdin) == NULL) {
      break;
    }
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '\0')
      continue;
    result = process_command(fd, &request_id, ip, sizeof(ip), &port, line);
    if (result == 1)
      break;
    if (result < 0)
      break;
  }
  close_socket(fd);
  network_cleanup();
  return 0;
}
