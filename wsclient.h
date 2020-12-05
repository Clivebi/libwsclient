#ifndef WSCLIENT_H_
#define WSCLIENT_H_

#include <stdint.h>
#include <sys/types.h>
#include <sys/un.h>
#include <stddef.h>

#include "config.h"

#define MAX_HTTP_HEADER_SIZE (4096*4)

#define FRAME_CHUNK_LENGTH 1024
#define HELPER_RECV_BUF_SIZE 1024

//wsclent flags
#define CLIENT_CONNECTED 		(1 << 0)
#define CLIENT_CONNECTING 		(1 << 1)
#define CLIENT_SHOULD_CLOSE 	(1 << 2)
#define CLIENT_SENT_CLOSE_FRAME (1 << 3)

typedef int WS_ERROR;


#define WS_ERROR_OK					0
#define WS_ERROR_MALLOC 			-1
#define WS_ERROR_UNEXPECTED_STATE 	-2
#define WS_ERROR_HANDSHAKE		  	-3
#define WS_ERROR_WRITE_ERROR		-4
#define WS_ERROR_HANDSHAKE_BAD_STATUS_ERR -5
#define WS_ERROR_HANDSHAKE_NO_UPGRADE_ERR -6
#define WS_ERROR_HANDSHAKE_NO_CONNECTION_ERR -7
#define WS_ERROR_HANDSHAKE_BAD_ACCEPT_ERR -8
#define WS_ERROR_SEND_AFTER_CLOSE_FRAME_ERR -9
#define WS_ERROR_COMPLETE_FRAME_MASKED_ERR -10
#define WS_ERROR_SEND_DURING_CONNECT_ERR -11
#define WS_ERROR_INVALID_PARAMETER -12
#define WS_ERROR_SEND_AFTER_SHOULD_CLOSE -13


typedef struct _ws_url {
	char scheme[6];
	char port[10];
	char*host;
	char*path;
}ws_url;


typedef struct _wsclient_frame {
	unsigned int fin;
	unsigned int opcode;
	unsigned int mask_offset;
	unsigned int payload_offset;
	unsigned int rawdata_idx;
	unsigned int rawdata_sz;
	unsigned long long payload_len;
	char *rawdata;
	struct _wsclient_frame *next_frame;
	struct _wsclient_frame *prev_frame;
	unsigned char mask[4];
} wsclient_frame;

typedef struct _wsclient_message {
	unsigned int opcode;
	unsigned long long payload_len;
	char *payload;
} wsclient_message;

typedef struct _wsclient {
	int flags;
	int (*onopen)(struct _wsclient *);
	//called when recv close control frame
	int (*onclose)(struct _wsclient *);
	//called when error 
	int (*onerror)(struct _wsclient *, WS_ERROR err,int extra_error);
	//called when receive server message
	int (*onmessage)(struct _wsclient *, wsclient_message *msg);
	//use by libuser,user can use this field to save private struct eg:socket
	void* context;
	//called when wsclient need write data to server,normal is socket_send or SSL_write
	int (*write)(struct _wsclient *,const void *buf,size_t length);
	wsclient_frame *current_frame;
	void* handshake_context;
} wsclient;

//
#define SET_ONOPEN_CALLBACK(c,callback) c->onopen = callback
#define SET_ONCLOSE_CALLBACK(c,callback) c->onclose = callback
#define SET_ONERROR_CALLBACK(c,callback) c->onerror = callback
#define SET_ONMESSAGE_CALLBACK(c,callback) c->onmessage = callback


//new wsclient object
wsclient *libwsclient_new();
//free wsclient,if not send close frame,send close frame
void libwsclient_free(wsclient *client);
//close websocket (send close frame)
void libwsclient_close(wsclient *client);
//when transport layer receive data,call this function to fire websocket envent
void libwsclient_data_arrived(wsclient*client,const void* buf,size_t size);
//start handshake with server
void libwsclient_start_handshake(wsclient*client,ws_url*url);
//send frame
int libwsclient_send_fragment(wsclient *client, char *strdata, int len, int flags);
//send text just warp of libwsclient_send_fragment
//for send text message
#define libwsclient_send(c, data, len) libwsclient_send_fragment(c, data, len, 0x81)
//for send binary message
#define libwsclient_send_bytes(c, data, len) libwsclient_send_fragment(c, data, len, 0x82)




//helper functions
//parse url text to url object eg:ws://echo.websocket.org/ or wss://echo.websocket.org/
ws_url* libwsclient_parse_url_string(const char *url);
//free URL resource
void libwsclient_free_url(ws_url *url);

#endif /* WSCLIENT_H_ */
