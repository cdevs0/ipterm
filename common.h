#ifndef COMMON_H
#define COMMON_H
#include <stddef.h>
#include <stdint.h>
#define MAGIC 0x43545231u
#define VERSION 1u
#define MAX_PAYLOAD 8192u
#define MAX_ARGS 16u
#define MAX_ARG 512u
enum { MSG_HELLO = 1, MSG_HELLO_OK, MSG_RUN, MSG_RESULT, MSG_ERROR };
struct frame {
  uint8_t type;
  uint32_t request_id;
  uint32_t length;
  unsigned char payload[MAX_PAYLOAD];
};
int send_all(int fd, const void *buf, size_t len);
int recv_all(int fd, void *buf, size_t len);
int send_frame(int fd, uint8_t type, uint32_t request_id, const void *payload,
               uint32_t length);
int recv_frame(int fd, struct frame *f);
#endif
