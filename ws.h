#include "stdio.h"
#include "stdlib.h"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "sha1.h"

#define BUFFER_SIZE 4096
#define MAX_EVENTS 1024

// setting the listen socket
// loop accept get an endpoint
// add endpoint in to the loop
// if the endpoint have receive data 
// read data and  parse it specify protocol

//struct epoll_event ev, events[MAX_EVENTS];
struct sockaddr_in servaddr;
//typedef struct server ws_server;
int listen_sock, epollfd,addrlen;

typedef struct frame
{
	int opcode;
	char * payload;
} ws_frame;

enum opcode{
	TEXT = 1,
	BINARY= 2,
	CLOSE = 8,
	PING = 9,
	PONG = 10,
};
typedef struct  client
{
	int fd;
	char * data;
	int size;
	int assgined;
	int state;

} ws_client;


typedef struct server
{
	ws_client * clients; //all of the connection client
	int client_size; // client scale
	int epollfd; //epoll listenfd
	struct epoll_event * events; //monitor event list
	int event_size; //
	int current_event_size;
	int max_fd; //current max fd

} ws_server;
ws_server * server = NULL;
char * unmask(char * mask_bytes,char * buffer,int buffer_size);
void handle_all_frame(ws_client * client,ws_frame * frame);
void handle_ping(ws_client * client);
void handle_data(ws_client * client,char * data,int data_size);
void handle_close(ws_client * client,int code,char * reason);
void handle_text(ws_client * client,char * payload,int payload_size);
void broadcast(char * msg);

