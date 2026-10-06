#include "common.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
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
#elif defined(__ANDROID__) || defined(__linux__) || defined(__APPLE__) ||      \
    defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) ||     \
    defined(__unix__) || defined(__unix)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET_VALUE (-1)
static void close_socket(socket_t s) { close(s); }
static int network_init(void) { return 0; }
static void network_cleanup(void) {}
#else
#error "Unsupported operating system"
#endif
static int command_allowed(const char *name) {
  (void)name;
  return 1;
}
static int split_arguments(unsigned char *data, uint32_t length, char *argv[],
                           char storage[][MAX_ARG], size_t *argc) {
  size_t count = 0;
  uint32_t pos = 0;
  while (pos < length) {
    uint32_t start;
    uint32_t n;
    while (pos < length && isspace((unsigned char)data[pos])) {
      ++pos;
    }
    if (pos == length)
      break;
    if (count >= MAX_ARGS)
      return -1;
    start = pos;
    while (pos < length && !isspace((unsigned char)data[pos])) {
      ++pos;
    }
    n = pos - start;
    if (n == 0 || n >= MAX_ARG)
      return -1;
    memcpy(storage[count], data + start, n);
    storage[count][n] = '\0';
    argv[count] = storage[count];
    ++count;
  }
  argv[count] = NULL;
  *argc = count;
  if (count == 0)
    return -1;
  return 0;
}
#if !defined(_WIN32)
static int execute_posix(const char *program, char *argv[], char *output,
                         size_t output_size, int *exit_status) {
  int pipefd[2];
  pid_t pid;
  size_t used = 0;
  if (pipe(pipefd) != 0)
    return -1;
  pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return -1;
  }
  if (pid == 0) {
    close(pipefd[0]);
    if (dup2(pipefd[1], STDOUT_FILENO) < 0)
      _exit(126);
    if (dup2(pipefd[1], STDERR_FILENO) < 0)
      _exit(126);
    close(pipefd[1]);
    execvp(program, argv);
    _exit(127);
  }
  close(pipefd[1]);
  while (used + 1 < output_size) {
    ssize_t bytes_read;
    bytes_read = read(pipefd[0], output + used, output_size - used - 1);
    if (bytes_read <= 0)
      break;
    used += (size_t)bytes_read;
  }
  output[used] = '\0';
  close(pipefd[0]);
  if (waitpid(pid, exit_status, 0) < 0)
    return -1;
  if (WIFEXITED(*exit_status)) {
    *exit_status = WEXITSTATUS(*exit_status);
  } else if (WIFSIGNALED(*exit_status)) {
    *exit_status = 128 + WTERMSIG(*exit_status);
  } else {
    *exit_status = 128;
  }
  return 0;
}
#endif
#if defined(_WIN32)
static int append_windows_argument(char *buffer, size_t buffer_size,
                                   size_t *used, const char *argument) {
  size_t i;
  size_t backslashes = 0;
  if (*used + 1 >= buffer_size)
    return -1;
  buffer[(*used)++] = '"';
  for (i = 0; argument[i] != '\0'; ++i) {
    char c = argument[i];
    if (c == '\\') {
      ++backslashes;
      continue;
    }
    if (c == '"') {
      size_t j;
      for (j = 0; j < backslashes * 2 + 1; ++j) {
        if (*used + 1 >= buffer_size)
          return -1;
        buffer[(*used)++] = '\\';
      }
      if (*used + 1 >= buffer_size)
        return -1;
      buffer[(*used)++] = '"';
      backslashes = 0;
      continue;
    }
    while (backslashes != 0) {
      if (*used + 1 >= buffer_size)
        return -1;
      buffer[(*used)++] = '\\';
      --backslashes;
    }
    if (*used + 1 >= buffer_size)
      return -1;
    buffer[(*used)++] = c;
  }
  while (backslashes != 0) {
    if (*used + 1 >= buffer_size)
      return -1;
    buffer[(*used)++] = '\\';
    --backslashes;
  }
  if (*used + 1 >= buffer_size)
    return -1;
  buffer[(*used)++] = '"';
  buffer[*used] = '\0';
  return 0;
}
static int execute_windows(const char *program, char *argv[], char *output,
                           size_t output_size, int *exit_status) {
  SECURITY_ATTRIBUTES sa;
  HANDLE read_pipe = NULL;
  HANDLE write_pipe = NULL;
  STARTUPINFOA startup_info;
  PROCESS_INFORMATION process_info;
  char command_line[MAX_PAYLOAD];
  size_t used = 0;
  size_t i;
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;
  if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
    return -1;
  }
  if (!SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle(read_pipe);
    CloseHandle(write_pipe);
    return -1;
  }
  command_line[0] = '\0';
  for (i = 0; argv[i] != NULL; ++i) {
    if (i != 0) {
      if (used + 1 >= sizeof(command_line)) {
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        return -1;
      }
      command_line[used++] = ' ';
      command_line[used] = '\0';
    }
    if (append_windows_argument(command_line, sizeof(command_line), &used,
                                argv[i]) != 0) {
      CloseHandle(read_pipe);
      CloseHandle(write_pipe);
      return -1;
    }
  }
  memset(&startup_info, 0, sizeof(startup_info));
  memset(&process_info, 0, sizeof(process_info));
  startup_info.cb = sizeof(startup_info);
  startup_info.dwFlags = STARTF_USESTDHANDLES;
  startup_info.hStdOutput = write_pipe;
  startup_info.hStdError = write_pipe;
  startup_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  if (!CreateProcessA(NULL, command_line, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                      NULL, NULL, &startup_info, &process_info)) {
    CloseHandle(read_pipe);
    CloseHandle(write_pipe);
    return -1;
  }
  CloseHandle(write_pipe);
  write_pipe = NULL;
  while (used + 1 < output_size) {
    DWORD bytes_read = 0;
    if (!ReadFile(read_pipe, output + used, (DWORD)(output_size - used - 1),
                  &bytes_read, NULL)) {
      break;
    }
    if (bytes_read == 0)
      break;
    used += (size_t)bytes_read;
  }
  output[used] = '\0';
  CloseHandle(read_pipe);
  WaitForSingleObject(process_info.hProcess, INFINITE);
  {
    DWORD process_exit_code = 1;
    if (GetExitCodeProcess(process_info.hProcess, &process_exit_code)) {
      *exit_status = (int)process_exit_code;
    } else {
      *exit_status = 1;
    }
  }
  CloseHandle(process_info.hProcess);
  CloseHandle(process_info.hThread);
  (void)program;
  return 0;
}
#endif
static int execute_command(const unsigned char *payload, uint32_t length,
                           char *output, size_t output_size, int *exit_status) {
  char storage[MAX_ARGS][MAX_ARG];
  char *argv[MAX_ARGS + 1];
  size_t argc;
  if (split_arguments((unsigned char *)payload, length, argv, storage, &argc) !=
      0) {
    return -1;
  }
  if (argc == 0)
    return -1;
  if (!command_allowed(argv[0]))
    return -2;
#if defined(_WIN32)
  return execute_windows(argv[0], argv, output, output_size, exit_status);
#else
  return execute_posix(argv[0], argv, output, output_size, exit_status);
#endif
}
static socket_t create_listener(unsigned short port) {
  socket_t s;
  int yes = 1;
  struct sockaddr_in addr;
  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET_VALUE)
    return INVALID_SOCKET_VALUE;
#if defined(_WIN32)
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes,
                 sizeof(yes)) != 0)
#else
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0)
#endif
  {
    close_socket(s);
    return INVALID_SOCKET_VALUE;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close_socket(s);
    return INVALID_SOCKET_VALUE;
  }
  if (listen(s, 8) != 0) {
    close_socket(s);
    return INVALID_SOCKET_VALUE;
  }
  return s;
}
static int authenticate(socket_t client) {
  struct frame f;
  if (recv_frame(client, &f) != 0)
    return -1;
  if (f.type != MSG_HELLO)
    return -1;
  if (f.length != 8 || memcmp(f.payload, "IPTENC!", 8) != 0) {
    const char error[] = "authentication failed";
    send_frame(client, MSG_ERROR, f.request_id, error, (uint32_t)strlen(error));
    return -1;
  }
  return send_frame(client, MSG_HELLO_OK, f.request_id, NULL, 0);
}
static void client_loop(socket_t client) {
  struct frame f;
  if (authenticate(client) != 0)
    return;
  for (;;) {
    char output[MAX_PAYLOAD - 4];
    int exit_status;
    int result;
    if (recv_frame(client, &f) != 0)
      return;
    if (f.type != MSG_RUN) {
      const char error[] = "unsupported command";
      send_frame(client, MSG_ERROR, f.request_id, error,
                 (uint32_t)strlen(error));
      continue;
    }
    result = execute_command(f.payload, f.length, output, sizeof(output),
                             &exit_status);
    if (result == -2) {
      const char error[] = "command is not in receiver allowlist";
      send_frame(client, MSG_ERROR, f.request_id, error,
                 (uint32_t)strlen(error));
      continue;
    }
    if (result != 0) {
      const char error[] = "execution failed";
      send_frame(client, MSG_ERROR, f.request_id, error,
                 (uint32_t)strlen(error));
      continue;
    }
    {
      unsigned char result_buffer[MAX_PAYLOAD];
      uint32_t status;
      size_t output_len;
      status = (uint32_t)exit_status;
      output_len = strlen(output);
      if (output_len > MAX_PAYLOAD - 4)
        output_len = MAX_PAYLOAD - 4;
      result_buffer[0] = (unsigned char)(status >> 24);
      result_buffer[1] = (unsigned char)(status >> 16);
      result_buffer[2] = (unsigned char)(status >> 8);
      result_buffer[3] = (unsigned char)status;
      memcpy(result_buffer + 4, output, output_len);
      send_frame(client, MSG_RESULT, f.request_id, result_buffer,
                 (uint32_t)(output_len + 4));
    }
  }
}
int main(int argc, char **argv) {
  unsigned long port = 9000;
  socket_t listener;
  if (argc > 1) {
    char *end = NULL;
    port = strtoul(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0') {
      fprintf(stderr, "invalid port\n");
      return 1;
    }
  }
  if (port == 0 || port > 65535) {
    fprintf(stderr, "invalid port\n");
    return 1;
  }
  if (network_init() != 0) {
    fprintf(stderr, "network initialization failed\n");
    return 1;
  }
  listener = create_listener((unsigned short)port);
  if (listener == INVALID_SOCKET_VALUE) {
    fprintf(stderr, "cannot create listener\n");
    network_cleanup();
    return 1;
  }
  printf("receiver listening on port %lu\n", port);
  fflush(stdout);
  for (;;) {
    socket_t client;
    client = accept(listener, NULL, NULL);
    if (client == INVALID_SOCKET_VALUE)
      continue;
    printf("controller connected\n");
    fflush(stdout);
    client_loop(client);
    close_socket(client);
    printf("controller disconnected\n");
    fflush(stdout);
  }
  close_socket(listener);
  network_cleanup();
  return 0;
}
