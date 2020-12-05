#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <signal.h>

#include "wsclient.h"

#define TEST_TEXT "Hello websocket"

typedef struct _user_context{
	int sockfd;
}user_context;

//tcp helper functions

int tcp_read(wsclient *c, void *buf, size_t length)
{
	user_context *ctx = c->context;
	return recv(ctx->sockfd, buf, length, 0);
}

int tcp_write(wsclient *c, const void *buf, size_t length)
{
	user_context *ctx = c->context;
	return send(ctx->sockfd, buf, length, 0);
}

int tcp_open_connection(wsclient *client, const char *host, const char *port)
{
	struct addrinfo hints, *servinfo, *p;
	int rv, sockfd;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0)
	{
		return rv;
	}

	for (p = servinfo; p != NULL; p = p->ai_next)
	{
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
		{
			continue;
		}
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
		{
			shutdown(sockfd,SHUT_RDWR);
			continue;
		}
		break;
	}
	freeaddrinfo(servinfo);
	if (p == NULL)
	{
		return -1;
	}
	return sockfd;
}


int onclose(wsclient *c)
{
	fprintf(stderr, "onclose called: %X\n", (int)c->context);
	return 0;
}

int onerror(struct _wsclient *client, WS_ERROR err, int extra_error)
{
	fprintf(stderr, "onerror: (%d): %d\n", err, extra_error);
	if (extra_error)
	{
		errno = extra_error;
		perror("recv");
	}
	return 0;
}

int onmessage(wsclient *c, wsclient_message *msg)
{
	fprintf(stderr, "onmessage: (%llu): %s\n", msg->payload_len, msg->payload);
	//close the connection,send close frame to server
	libwsclient_close(c);
	return 0;
}

int onopen(wsclient *c)
{
	fprintf(stderr, "onopen called: %X\n", (int)c->context);
	libwsclient_send_bytes(c, TEST_TEXT, (strlen(TEST_TEXT)));
	return 0;
}

void *async_read_thread(void *ptr)
{
	int size = 0;
	unsigned char buf[1024] = {0};
	wsclient *c = (wsclient *)ptr;
	while (1)
	{
		if (c->flags & CLIENT_SHOULD_CLOSE || c->flags & CLIENT_SENT_CLOSE_FRAME)
		{
			fprintf(stderr,"client closed\n");
			break;
		}
		size = tcp_read(c, buf, 1024);
		if (size <= 0)
		{
			fprintf(stderr,"transport read thread failed");
			break;
		}
		//step6: when read complete,write data to websocket stack
		//if the frame is not control frame,onmessage callback will be called
		libwsclient_data_arrived(c, buf, size);

	}
	return NULL;
}

int main(int argc, char **argv)
{
	user_context ctx = {0};
	pthread_t  thread;
	ws_url *url = libwsclient_parse_url_string("ws://localhost:5601");
	if (url == NULL)
	{
		fprintf(stderr,"parse URL failed\n");
		return -1;
	}
	//step1: create client instance
	wsclient *client = libwsclient_new();
	//step2: set callback functions for this client
	SET_ONOPEN_CALLBACK(client, &onopen);
	SET_ONERROR_CALLBACK(client, &onerror);
	SET_ONMESSAGE_CALLBACK(client, &onmessage);
	SET_ONCLOSE_CALLBACK(client, &onclose);

	//
	//step3: connect tcp to remote server,setup transport write pointer
	fprintf(stderr,"connect to %s:%s\%s\n", url->host, url->port,url->path);
	ctx.sockfd = tcp_open_connection(client, url->host, url->port);
	if (ctx.sockfd <= 0)
	{
		errno = ctx.sockfd;
		perror("connect");
		return ctx.sockfd;
	}
	client->context = &ctx;
	client->write = &tcp_write;
	//step4: async read tcp , in this case ,start a read thread like async i/o
	pthread_create(&thread,NULL,async_read_thread,client);

	//step5: start handshake,
	//if handshake successfully,the onopen callback will be called,or on error called
	libwsclient_start_handshake(client, url);

	//wait complete and do clean up
	pthread_join(thread,NULL);

	//step7:clear up
	shutdown(ctx.sockfd,SHUT_RDWR);

	libwsclient_free(client);

	return 0;
}
