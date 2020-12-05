libwsclient
===========


WebSocket client library for C

fork from payden/libwsclient 

This library abstracts away WebSocket protocol framing for
client connections.  It aims to provide a *somewhat* similar
API to the implementation in your browser.  You create a new
client context and create callbacks to be triggered when
certain events occur (onopen, onmessage, onclose, onerror).

Your best bet for getting started is to look at test.c which shows
how to connect to an echo server using libwsclient calls.

Also, to install:

./autogen.sh

./configure && make && sudo make install

Then link your C program against wsclient: 'gcc -g -O2 -o test test.c -lwsclient'


Upgrade instructions:
The network IO interface and websocket stack code are isolated to facilitate the use of gdcasyncsocket in various asynchronous IO environments, such as IOS. Multithreading support is removed in this version. Therefore, it is recommended to use code in an independent thread of asynchronous io. Please refer to test.C for use

```
    user_context ctx = {0};
	pthread_t  thread;
	ws_url *url = libwsclient_parse_url_string("ws://localhost:5601");
	if (url == NULL)
	{
		fprintf(stderr,"parse URL failed\n");
		return -1;
	}
	//step 1: create client instance
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
```