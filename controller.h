#ifndef CONTROLLER_H
#define CONTROLLER_H
#include <stddef.h>
#define CTRL_MAX_LINE 1024
#define CTRL_MAX_INTERFACE 128
#define CTRL_MAX_ADDRESS 64
#define CTRL_MAX_NAME 64
#define CTRL_MAX_SESSION 128
enum command_type {
  CMD_INVALID = 0,
  CMD_SET_IP,
  CMD_SET_NAME,
  CMD_SET_SESSION
};
struct command {
  enum command_type type;
  union {
    struct {
      char interface_name[CTRL_MAX_INTERFACE];
      char address[CTRL_MAX_ADDRESS];
      unsigned prefix;
    } set_ip;
    struct {
      char name[CTRL_MAX_NAME];
    } set_name;
    struct {
      char id[CTRL_MAX_SESSION];
    } set_session;
  } data;
};
int controller_parse_command(const char *line, struct command *command);
int controller_validate_command(const struct command *command);
int controller_execute_command(const struct command *command);
const char *controller_command_name(enum command_type type);
#endif
