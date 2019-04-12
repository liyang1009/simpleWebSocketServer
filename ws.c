#include "ws.h"
static int
create_and_bind (char *port){ 

  	struct addrinfo hints;
  	struct addrinfo *result, *rp;
  	int s, sfd;                  
  	memset (&hints, 0, sizeof (struct addrinfo));
  	hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
  	hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
  	hints.ai_flags = AI_PASSIVE;     /* All interfaces */

  	s = getaddrinfo (NULL, port, &hints, &result);
  	if (s != 0){
      fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
      return -1;               
    }
  
 	for (rp = result; rp != NULL; rp = rp->ai_next){
    	sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      	if (sfd == -1)           
        	continue;              
  
      	s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
      	if (s == 0)              
        {
          /* We managed to bind successfully! */
        	break;
        }
  
      	close (sfd);
    }
  
  	if (rp == NULL){
    	fprintf (stderr, "Could not bind\n");
      	return -1;               
    }
  
  	freeaddrinfo (result);       
  
  	return sfd;                  
} 

int setNonblocking(int sfd){

	int flags, s;

	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1){
	    perror ("fcntl");
	    return -1;
	}

	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
	if (s == -1){
	    perror ("fcntl");
	    return -1;
	}

	return 0;           
}     


void * create_client(int fd,ws_server * server){

	if(server->max_fd < fd){
		//server->clients = realloc(server->client);
		server->max_fd = fd;
		server->clients = (ws_client * )realloc(server->clients,fd*sizeof(ws_client));
	}
	ws_client * client = &server->clients[fd];
	client->data = (char * ) malloc(sizeof(char)*BUFFER_SIZE + 1);
	client->size = BUFFER_SIZE;
	client->data[client->size] = '\0';
	client->assgined =0;
	client->state = 0;
	client->fd = fd;
	//return client;
}

void* close_client(ws_client * client){
	if(client != NULL){
		
		close(client->fd);
		free(client->data);
		if(client->fd < server->max_fd){
			server->clients[client->fd] = (struct client){0};// delete the client
		}
	}
}

ws_frame* get_frame(ws_client* client){

	char buffer[BUFFER_SIZE];
	int read_size = read(client->fd,buffer,BUFFER_SIZE);
	if(read_size <= 0){
		close_client(client);
		return NULL;
	}
	if(read_size > client->size - client->assgined){

		 //reallocate the client's buffer
		client->data =(char * ) realloc(client->data,client->size+ read_size *2 + 1);
		if(client->data){
			client->size =  client->size+ read_size *2;
			client->data[client->size] = '\0';
		}else{
			return;
		}

	}
	int offset = client->assgined ;
	char * copy_str = client->data + offset;
	memcpy(copy_str,buffer,read_size);
	client->assgined += read_size;

	if(!client->state){
		int result = handle_verify(client);
		if(!result){
			//close_client(client);
			return;
		}
	}

	//get websocket frame
	if(client->data && client->state == 1){
		int idx = 2;
		char byte_one = client->data[0];
		uint opcode = byte_one & 0x0f;
		char byte_two = client->data[1];
		int mask =  byte_two&0x80;
		uint16_t len = byte_two&0x7f;
		if(opcode >125){
			if(client->assgined<8){
				close_client(client);
				return;
			}
		}
		if(len == 126){
			len = *((uint16_t*)client->data[2]);
			idx +=2;
		}else if (len == 127){
			uint32_t highBits = *(uint32_t*)client->data[2];
			if(highBits != 0){

			}
			len = *(uint32_t*)client->data[5];
			idx += 8;
			
		}
		if(client->assgined < idx + 4 + len){
			return NULL;
		}
		char mask_bytes[4];
		memcpy(mask_bytes,client->data+idx,4);
		idx+=4;
		char * payload = client->data + idx;
		payload = unmask(mask_bytes,payload,len); //get payload to handle_all_frame and end  have to destory the memory area
		memset(client->data,'0',idx+len);//
		char * remain = client->data+idx + len;
		client->assgined = client->assgined - idx - len;
		memcpy(client->data,remain,client->assgined);

		//construct ws frame
		ws_frame * frame = (ws_frame * )malloc(sizeof(ws_frame));
		frame->opcode = opcode;
		frame->payload = payload;
		handle_all_frame(client,frame);

	}

}


/*verify the http handshark and then hjack to websocket else close the client*/
int handle_verify(ws_client * client){

	if(!client->state){
		//get all http request data and then parse it
		//split the request and then get the  header "sec-websocket-key" and the get the value

		char * http_header = strstr(client->data,"\r\n\r\n");
		if(http_header){

			char * start = NULL;
			start = strstr(client->data,"Sec-WebSocket-Key");
			if(start != NULL){
				char * end = strstr(start,"\r\n");
				char sec[255]={0};
				strncpy(sec,start,end-start);	
				
				static char * const_key = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";	
				char secure_key[255]={0};
				char * key = strstr(sec,":")+2;
				sprintf(secure_key,"%s%s",key,const_key);
				key = get_socket_secure_key(secure_key);
				char *  res_header_str= "HTTP/1.1 101 Web Socket Protocol Handshake\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s%s";
				char * double_newline = "\r\n\r\n";;
				char msg[255] = {0};
				sprintf(msg,res_header_str,key,double_newline); 
				if(write(client->fd,msg,strlen(msg)) <= 0){
					close_client(client);
				}

				int http_header_len = http_header - client->data + 4;

				//copy the remain data 
				memset(client->data,'0',http_header_len);//
				char * remain = client->data+http_header_len;
				client->assgined = client->assgined - http_header_len;
				memcpy(client->data,remain,client->assgined);
				client->state = 1;
				free(key);
			}
		}
	
	}

	return 0;

}

void send_frame(ws_client * client,int opcode,char * payload,int payload_size){

	int frame_size = payload_size ;
	char op_code =  0x80|opcode;
	char b2 = 0;
	char * frame_data =NULL;
	if( payload_size <126 ){
		frame_size += 2;
		frame_data =(char *) malloc(sizeof(char)*frame_size+1);
		frame_data[0] = op_code;
		b2 |= payload_size;
		frame_data[1] = b2;
		memcpy(frame_data+2,payload,payload_size);
	}else if( payload_size == 126 ){

		frame_size += 4;
		frame_data = (char  * )malloc(sizeof(char )*frame_size+1);
		frame_data[0] = op_code;
		b2 |= payload_size;
		frame_data[1] = b2;
		char * payload_size_extra = (char *) &payload_size;
		frame_data[2] = payload_size_extra[0];
		frame_data[3] = payload_size_extra[1];
		memcpy(frame_data+4,payload,payload_size);

	} else{

		frame_size += 10;
		b2|= 127;
		frame_data = (char  * )malloc(sizeof(char )*frame_size+1);
		frame_data[0] = op_code;
		frame_data[1] = b2;
		frame_data[2] = (0 >> 24) & 0xFF;
		frame_data[3] = (0 >> 16) & 0xFF;
		frame_data[4] = (0 >> 8) & 0xFF;
		frame_data[5] = 0 & 0xFF;
		frame_data[6] = (payload_size >> 24) & 0xFF;
		frame_data[7] = (payload_size >> 16) & 0xFF;
		frame_data[8] = (payload_size >> 8) & 0xFF;
		frame_data[9] = payload_size & 0xFF;
		memcpy(frame_data+10,payload,payload_size);
 
	}
	if(frame_data){	
		frame_data[frame_size] = '\0';
		write(client->fd,frame_data,frame_size);
		free(frame_data);
	}


}
void handle_all_frame(ws_client * client,ws_frame * frame){
	if(frame == NULL){
		return;
	}
	//handle the ws_frame
	enum opcode enum_opcode = (enum opcode) frame->opcode;
	switch(frame->opcode){
		case TEXT:
			//handle_text(client,frame->payload,strlen(frame->payload));
			broadcast(frame->payload);	
			break;
		case BINARY:
			break;
		case CLOSE:
			if(strlen(frame->payload)>2){
				
			}
			short close_code =(short) *(frame->payload);
			char * reason = &frame->payload[2];
			handle_close(client,close_code,reason);
			break;
		case PING:
			handle_ping(client);
			break;
		case PONG:
			break;
		default:
			handle_close(client,1002,"unknown opcode");
	}
	if(frame){
		//case the opcode and then execute specify  opcode-handler
		free(frame->payload);
		free(frame);
	}

}

void handle_text(ws_client * client,char * payload,int payload_size){
//handler the raw data
	enum opcode enum_opcode = TEXT;
	send_frame(client,enum_opcode,payload,payload_size);
}
void handle_ping(ws_client * client){
//handler ping data send pong
	char * payload = "pong pong";
	enum opcode enum_opcode = PONG;
	send_frame(client,enum_opcode,payload,strlen(payload));

}
void handle_close(ws_client * client,int code,char * reason){
	//handle the close
	int reason_size = strlen(reason);
	enum opcode close_opcode = CLOSE;
	int payload_size = reason_size + 2;
	char * payload =(char *) malloc(sizeof(char )* payload_size);
	payload[0] = (code >> 24) & 0xFF;
	payload[1] = (code >> 16) & 0xFF;
	memcpy(payload,reason,2);
	send_frame(client,close_opcode,payload,payload_size);
	// remove the fd in epoll event set and close the socket
	free(payload);
	close_client(client);
}

char * unmask(char * mask_bytes,char * buffer,int buffer_size){

	char * payload = (char * )malloc(sizeof(char )*buffer_size+1);
	int mod = 0;
	int i;
	for(i = 0;i<buffer_size;i++){
		mod = i%4;
		payload[i] = mask_bytes[mod]^buffer[i];
	}
	payload[buffer_size] = '\0';
	return payload;
}


void event_loop(ws_server * server ){
      
    /* Code to set up listening socket, 'listen_sock',
    (socket(), bind(), listen()) omitted */  
   int conn_sock,nfds;   
   for (;;) {
       nfds = epoll_wait(server->epollfd,server->events, MAX_EVENTS, -1);
       if (nfds == -1) {
           perror("epoll_wait");
           //exit(EXIT_FAILURE);
       }
       int n ,client_index;
       for (n = 0; n < nfds; ++n) {
           if (server->events[n].data.fd == listen_sock) {
               conn_sock = accept(listen_sock,
                                  (struct sockaddr *) &servaddr, &addrlen);
               if (conn_sock == -1) {
                   perror("accept");
                   //exit(EXIT_FAILURE);
               }
               //int  flags = fcntl(fd, F_GETFL, 0);
			   //fcntl(conn_sock, F_SETFL, flags | O_NONBLOCK);
               setNonblocking(conn_sock);
               struct epoll_event ev = {0}; 
               ev.events = EPOLLIN | EPOLLET;
               ev.data.fd = conn_sock;

               //if(server->current_event_size == )
               if (epoll_ctl(server->epollfd, EPOLL_CTL_ADD, conn_sock,
                           &ev) == -1) {
                	perror("epoll_ctl: conn_sock");
                	//exit(EXIT_FAILURE);    
                }
               	server->current_event_size +=1;
          	create_client(ev.data.fd,server);

           } else {
		
		client_index = server->events[n].data.fd;
               	get_frame(&server->clients[client_index]);
           }
       }
   }

}

ws_server *  create_server(){
    
  
   	int s; 
	struct epoll_event ev;
    	listen_sock = create_and_bind("8088"); 
	setNonblocking(listen_sock);
	s = listen (listen_sock, MAX_EVENTS);   
	if(s<0){
		printf("error listen");
	}
	server = (ws_server * )malloc(sizeof(ws_server));
  	server->epollfd = epoll_create1(0);
	server->events = calloc(MAX_EVENTS,sizeof(ev)); 
	server->max_fd=MAX_EVENTS;
	server->clients = (ws_client * ) malloc(sizeof(ws_client)*MAX_EVENTS);
       	if (epollfd == -1) {
          perror("epoll_create1");
           exit(EXIT_FAILURE);
       	}
       	ev.events = EPOLLIN;
       	ev.data.fd = listen_sock;
       	if (epoll_ctl(server->epollfd, EPOLL_CTL_ADD, listen_sock, &ev) == -1) {
       	    perror("epoll_ctl: listen_sock");
       	    exit(EXIT_FAILURE);
       	}
       	return server;
}
void broadcast(char * msg){
	
	int msg_len = strlen(msg);
	int client_idx;
	for( client_idx = 0;client_idx<server->max_fd;client_idx++){
		ws_client * client = &server->clients[client_idx];
		if(client !=NULL&&client->state != 0){
			handle_text(client,msg,msg_len);
		}
	}
}

int main(int argc,char ** argv){

	server = create_server();
	event_loop(server);


	return 1;
}
