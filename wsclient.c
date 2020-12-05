#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#include "config.h"
#include "sha1.h"
#include "wsclient.h"

#ifndef MIN
#define MIN(a, b) (a < b ? a : b)
#endif

#define REQUEST_HAS_CONNECTION (1 << 0)
#define REQUEST_HAS_UPGRADE (1 << 1)
#define REQUEST_VALID_STATUS (1 << 2)
#define REQUEST_VALID_ACCEPT (1 << 3)
#define WS_FRAGMENT_START (1 << 0)
#define WS_FRAGMENT_FIN (1 << 7)

//internal functions
//this struct is used in lib and not export
#define internal
internal typedef struct _handshake_context
{
	char *key;
	char *key_hash;
	char *content;
	size_t allocate_size;
	size_t offset;
} handshake_context;

internal handshake_context *libwsclient_new_handshake_context(size_t cap);
internal void libwsclient_free_handshake_context(handshake_context *ctx);
internal WS_ERROR libwsclient_process_handshake(wsclient *client, const unsigned char *buf, size_t size, size_t *read_count);
internal void libwsclient_process_error(wsclient *client, WS_ERROR error, int extra_error);
internal void libwsclient_handle_control_frame(wsclient *c, wsclient_frame *ctl_frame);
internal void libwsclient_in_data(wsclient *c, char in);
internal void libwsclient_dispatch_message(wsclient *c, wsclient_frame *current);
internal void libwsclient_cleanup_frames(wsclient_frame *first);
internal int libwsclient_complete_frame(wsclient *c, wsclient_frame *frame);

int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen);

int stricmp(const char *s1, const char *s2);

ws_url *libwsclient_parse_url_string(const char *urlstring)
{
	size_t size = strlen(urlstring);
	size_t offset_port = 0;
	size_t offset_path = 0;
	size_t offset_host = 0;
	size_t host_size = 0;
	int found_path = 0;
	const char *host = NULL;

	ws_url *url = malloc(sizeof(ws_url));
	if (url == NULL)
	{
		return NULL;
	}
	memset(url, 0, sizeof(ws_url));
	if (memcmp(urlstring, "ws://", 5) == 0)
	{
		strcpy(url->scheme, "ws://");
		strcpy(url->port, "80");
		offset_host = 5;
	}
	else if (memcmp(urlstring, "wss://", 6) == 0)
	{
		strcpy(url->scheme, "wss://");
		strcpy(url->port, "443");
		offset_host = 6;
	}
	else
	{
		libwsclient_free_url(url);
		return NULL;
	}
	host = urlstring + offset_host;
	for (size_t i = offset_host; i < size; i++)
	{
		if (urlstring[i] == ':')
		{
			if (offset_port == 0)
			{
				offset_port = i + 1;
				host_size = i - offset_host;
			}
			else
			{
				libwsclient_free_url(url);
				return NULL;
			}
			continue;
		}
		if (urlstring[i] == '/')
		{
			found_path = 1;
			if (offset_port == 0)
			{
				host_size = i - offset_host;
			}
			else
			{
				size_t port_size = i - offset_port;
				if (port_size > 9)
				{
					libwsclient_free_url(url);
					return NULL;
				}
				strncpy(url->port, urlstring + offset_port, port_size);
			}
			url->host = malloc(host_size + 1);
			strncpy(url->host, urlstring + offset_host, host_size);
			url->host[host_size] = 0;
			url->path = strdup(urlstring + i);
			if (url->path == NULL)
			{
				libwsclient_free_url(url);
				return NULL;
			}
			break;
		}
	}
	if (found_path == 0)
	{
		if (offset_port == 0)
		{
			url->host = strdup(urlstring + offset_host);
		}
		else
		{
			size_t port_size = size - offset_port;
			if (port_size > 9)
			{
				libwsclient_free_url(url);
				return NULL;
			}
			strncpy(url->port, urlstring + offset_port, port_size);
			url->host = malloc(host_size + 1);
			strncpy(url->host, urlstring + offset_host, host_size);
			url->host[host_size] = 0;
		}
		url->path = strdup("/");
		if (url->path == NULL)
		{
			libwsclient_free_url(url);
			return NULL;
		}
	}
	return url;
}

void libwsclient_free_url(ws_url *url)
{
	if (url == NULL)
	{
		return;
	}
	if (url->host != NULL)
	{
		free(url->host);
	}
	if (url->path != NULL)
	{
		free(url->path);
	}
	free(url);
}

handshake_context *
libwsclient_new_handshake_context(size_t cap)
{
	handshake_context *ctx = malloc(sizeof(handshake_context));
	if (ctx != NULL)
	{
		memset(ctx, 0, sizeof(handshake_context));
		ctx->content = malloc(cap);
		if (ctx->content == NULL)
		{
			free(ctx);
			return NULL;
		}
		ctx->allocate_size = cap;
	}
	return ctx;
}

void libwsclient_free_handshake_context(handshake_context *ctx)
{
	if (ctx != NULL)
	{
		if (ctx->content != NULL)
		{
			free(ctx->content);
		}
		if (ctx->key != NULL)
		{
			free(ctx->key);
		}
		if (ctx->key_hash != NULL)
		{
			free(ctx->key_hash);
		}
		free(ctx);
	}
}

void libwsclient_handle_control_frame(wsclient *c, wsclient_frame *ctl_frame)
{
	wsclient_frame *ptr = NULL;
	int i, n = 0;
	char mask[4];
	int mask_int;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_sec * tv.tv_usec);
	mask_int = rand();
	memcpy(mask, &mask_int, 4);
	switch (ctl_frame->opcode)
	{
	case 0x8:
		//close frame
		if ((c->flags & CLIENT_SENT_CLOSE_FRAME) == 0)
		{
			//server request close.  Send close frame as acknowledgement.
			for (i = 0; i < ctl_frame->payload_len; i++)
				*(ctl_frame->rawdata + ctl_frame->payload_offset + i) ^= (mask[i % 4] & 0xff); //mask payload
			*(ctl_frame->rawdata + 1) |= 0x80;												   //turn mask bit on
			i = 0;
			while (i < ctl_frame->payload_offset + ctl_frame->payload_len && n >= 0)
			{
				n = c->write(c, ctl_frame->rawdata + i, ctl_frame->payload_offset + ctl_frame->payload_len - i);
				i += n;
			}
			if (n < 0)
			{
				libwsclient_process_error(c, WS_ERROR_WRITE_ERROR, n);
			}
		}
		c->flags |= CLIENT_SHOULD_CLOSE;
		break;
	default:
		fprintf(stderr, "Unhandled control frame received.  Opcode: %d\n", ctl_frame->opcode);
		break;
	}

	ptr = ctl_frame->prev_frame; //This very well may be a NULL pointer, but just in case we preserve it.
	free(ctl_frame->rawdata);
	memset(ctl_frame, 0, sizeof(wsclient_frame));
	ctl_frame->prev_frame = ptr;
	ctl_frame->rawdata = (char *)malloc(FRAME_CHUNK_LENGTH);
	memset(ctl_frame->rawdata, 0, FRAME_CHUNK_LENGTH);
}

void libwsclient_in_data(wsclient *c, char in)
{
	wsclient_frame *current = NULL, *new = NULL;
	unsigned char payload_len_short;
	if (c->current_frame == NULL)
	{
		c->current_frame = (wsclient_frame *)malloc(sizeof(wsclient_frame));
		memset(c->current_frame, 0, sizeof(wsclient_frame));
		c->current_frame->payload_len = -1;
		c->current_frame->rawdata_sz = FRAME_CHUNK_LENGTH;
		c->current_frame->rawdata = (char *)malloc(c->current_frame->rawdata_sz);
		memset(c->current_frame->rawdata, 0, c->current_frame->rawdata_sz);
	}
	current = c->current_frame;
	if (current->rawdata_idx >= current->rawdata_sz)
	{
		current->rawdata_sz += FRAME_CHUNK_LENGTH;
		current->rawdata = (char *)realloc(current->rawdata, current->rawdata_sz);
		memset(current->rawdata + current->rawdata_idx, 0, current->rawdata_sz - current->rawdata_idx);
	}
	*(current->rawdata + current->rawdata_idx++) = in;
	if (libwsclient_complete_frame(c, current) == 1)
	{
		if (current->fin == 1)
		{
			//is control frame
			if ((current->opcode & 0x08) == 0x08)
			{
				libwsclient_handle_control_frame(c, current);
			}
			else
			{
				libwsclient_dispatch_message(c, current);
				c->current_frame = NULL;
			}
		}
		else
		{
			new = (wsclient_frame *)malloc(sizeof(wsclient_frame));
			memset(new, 0, sizeof(wsclient_frame));
			new->payload_len = -1;
			new->rawdata = (char *)malloc(FRAME_CHUNK_LENGTH);
			memset(new->rawdata, 0, FRAME_CHUNK_LENGTH);
			new->prev_frame = current;
			current->next_frame = new;
			c->current_frame = new;
		}
	}
}

void libwsclient_dispatch_message(wsclient *c, wsclient_frame *current)
{
	unsigned long long message_payload_len, message_offset;
	int message_opcode, i;
	char *message_payload;
	wsclient_frame *first = NULL;
	wsclient_message *msg = NULL;
	if (current == NULL)
	{
		return;
	}
	message_offset = 0;
	message_payload_len = current->payload_len;
	for (; current->prev_frame != NULL; current = current->prev_frame)
	{
		message_payload_len += current->payload_len;
	}
	first = current;
	message_opcode = current->opcode;
	message_payload = (char *)malloc(message_payload_len + 1);
	memset(message_payload, 0, message_payload_len + 1);
	for (; current != NULL; current = current->next_frame)
	{
		memcpy(message_payload + message_offset, current->rawdata + current->payload_offset, current->payload_len);
		message_offset += current->payload_len;
	}

	libwsclient_cleanup_frames(first);
	msg = (wsclient_message *)malloc(sizeof(wsclient_message));
	memset(msg, 0, sizeof(wsclient_message));
	msg->opcode = message_opcode;
	msg->payload_len = message_offset;
	msg->payload = message_payload;
	if (c->onmessage != NULL)
	{
		c->onmessage(c, msg);
	}
	else
	{
		fprintf(stderr, "No onmessage call back registered with libwsclient.\n");
	}
	free(msg->payload);
	free(msg);
}
void libwsclient_cleanup_frames(wsclient_frame *first)
{
	wsclient_frame *this = NULL;
	wsclient_frame *next = first;
	while (next != NULL)
	{
		this = next;
		next = this->next_frame;
		if (this->rawdata != NULL)
		{
			free(this->rawdata);
		}
		free(this);
	}
}

int libwsclient_complete_frame(wsclient *c, wsclient_frame *frame)
{
	int payload_len_short, i;
	unsigned long long payload_len = 0;
	if (frame->rawdata_idx < 2)
	{
		return 0;
	}
	frame->fin = (*(frame->rawdata) & 0x80) == 0x80 ? 1 : 0;
	frame->opcode = *(frame->rawdata) & 0x0f;
	frame->payload_offset = 2;
	if ((*(frame->rawdata + 1) & 0x80) != 0x0)
	{
		libwsclient_process_error(c, WS_ERROR_COMPLETE_FRAME_MASKED_ERR, 0);
		return 0;
	}
	payload_len_short = *(frame->rawdata + 1) & 0x7f;
	switch (payload_len_short)
	{
	case 126:
		if (frame->rawdata_idx < 4)
		{
			return 0;
		}
		for (i = 0; i < 2; i++)
		{
			memcpy((void *)&payload_len + i, frame->rawdata + 3 - i, 1);
		}
		frame->payload_offset += 2;
		frame->payload_len = payload_len;
		break;
	case 127:
		if (frame->rawdata_idx < 10)
		{
			return 0;
		}
		for (i = 0; i < 8; i++)
		{
			memcpy((void *)&payload_len + i, frame->rawdata + 9 - i, 1);
		}
		frame->payload_offset += 8;
		frame->payload_len = payload_len;
		break;
	default:
		frame->payload_len = payload_len_short;
		break;
	}
	if (frame->rawdata_idx < frame->payload_offset + frame->payload_len)
	{
		return 0;
	}
	return 1;
}

wsclient *libwsclient_new()
{
	wsclient *client = NULL;
	client = (wsclient *)malloc(sizeof(wsclient));
	if (client == NULL)
	{
		return NULL;
	}
	memset(client, 0, sizeof(wsclient));
	return client;
}

int libwsclient_send_close_frame(wsclient *client)
{
	char data[6];
	int i = 0, n, mask_int;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_sec * tv.tv_usec);
	mask_int = rand();
	memcpy(data + 2, &mask_int, 4);
	data[0] = 0x88;
	data[1] = 0x80;
	do
	{
		n = client->write(client, data, 6);
		i += n;
	} while (i < 6 && n > 0);
	if (n < 0)
	{
		libwsclient_process_error(client, WS_ERROR_WRITE_ERROR, 0);
	}
	return n;
}


void libwsclient_close(wsclient *client)
{
	if (client == NULL)
	{
		return;
	}
	if(!(client->flags & CLIENT_CONNECTED)){
		return;
	}
	if (!(client->flags & CLIENT_SENT_CLOSE_FRAME))
	{
		libwsclient_send_close_frame(client);
		client->flags |= CLIENT_SENT_CLOSE_FRAME;
	}
}

void libwsclient_free(wsclient *client)
{
	if (client == NULL)
	{
		return;
	}
	libwsclient_close(client);
	if (client->current_frame != NULL)
	{
		libwsclient_cleanup_frames(client->current_frame);
		client->current_frame = NULL;
	}
	if (client->handshake_context != NULL)
	{
		libwsclient_free_handshake_context(client->handshake_context);
		client->handshake_context = NULL;
	}
	free(client);
}

void libwsclient_process_error(wsclient *client, WS_ERROR error, int extra_error)
{
	client->flags |= CLIENT_SHOULD_CLOSE;
	if (client->onerror != NULL)
	{
		client->onerror(client, error, extra_error);
	}
}

void libwsclient_data_arrived(wsclient *client, const void *buf, size_t size)
{
	WS_ERROR err = 0;
	char *data = NULL;
	size_t read_count = 0;
	if (client->flags & CLIENT_CONNECTING)
	{
		err = libwsclient_process_handshake(client, buf, size, &read_count);
		if (err != WS_ERROR_OK)
		{
			libwsclient_process_error(client, err, 0);
			return;
		}
		if (client->flags & CLIENT_CONNECTING)
		{
			printf("handshake not complete");
			return;
		}
		if (client->flags & CLIENT_CONNECTED && client->onopen != NULL)
		{
			client->onopen(client);
		}
		handshake_context *ctx = client->handshake_context;
		data = strstr(ctx->content, "\r\n\r\n");
		if (data - ctx->content + 4 < ctx->offset)
		{
			data += 4;
			for (size_t i = 0; i < ctx->offset; i++)
			{
				libwsclient_in_data(client, data[i]);
			}
		}
		libwsclient_free_handshake_context(ctx);
		client->handshake_context = NULL;
		return;
	}
	data = (char *)buf;
	for (size_t i = 0; i < size; i++)
	{
		libwsclient_in_data(client, data[i]);
	}
}

void libwsclient_init_handshake_context(handshake_context *ctx)
{
	SHA1_CTX sha1_ctx = {0};
	char key[128] = {0};
	char buffer[512] = {0};
	unsigned char key_nonce[20] = {0};

	srand(time(NULL));
	for (int z = 0; z < 16; z++)
	{
		key_nonce[z] = rand() & 0xff;
	}
	base64_encode(key_nonce, 16, key, 128);
	snprintf(buffer, sizeof(buffer), "%s%s", key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
	SHA1Init(&sha1_ctx);
	SHA1Update(&sha1_ctx, (unsigned char*)buffer, strlen(buffer));
	SHA1Final(key_nonce, &sha1_ctx);
	memset(buffer, 0, sizeof(buffer));
	base64_encode(key_nonce, 20, buffer, sizeof(buffer));
	ctx->key = strdup(key);
	ctx->key_hash = strdup(buffer);
}

void libwsclient_start_handshake(wsclient *client, ws_url *url)
{
	int n = 0;
	if (client->handshake_context != NULL)
	{
		return;
	}
	client->flags = CLIENT_CONNECTING;
	handshake_context *handshake_ctx = libwsclient_new_handshake_context(MAX_HTTP_HEADER_SIZE);
	if (handshake_ctx == NULL)
	{
		libwsclient_process_error(client, WS_ERROR_MALLOC, 0);
		return;
	}
	client->handshake_context = handshake_ctx;
	libwsclient_init_handshake_context(handshake_ctx);
	if (strcmp(url->port, "80") != 0)
	{
		n = snprintf(handshake_ctx->content, handshake_ctx->allocate_size, "GET %s HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nHost: %s:%s\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", url->path, url->host, url->port, handshake_ctx->key);
	}
	else
	{
		n = snprintf(handshake_ctx->content, handshake_ctx->allocate_size, "GET %s HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nHost: %s\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", url->path, url->host, handshake_ctx->key);
	}
	n = client->write(client, handshake_ctx->content, n);
	if (n < 0)
	{
		libwsclient_process_error(client, WS_ERROR_WRITE_ERROR, n);
		return;
	}
}

WS_ERROR libwsclient_process_handshake(wsclient *client, const unsigned char *buf, size_t size, size_t *read_count)
{
	size_t fetch_size = 0;
	char *tok = NULL;
	char *p = NULL;
	int flags = 0;

	handshake_context *ctx = (handshake_context *)client->handshake_context;
	if (client->handshake_context == NULL)
	{
		*read_count = 0;
		return WS_ERROR_UNEXPECTED_STATE;
	}
	fetch_size = MIN(size, (ctx->allocate_size - ctx->offset - 1));
	memcpy(&ctx->content[ctx->offset], buf, fetch_size);
	ctx->offset += fetch_size;
	ctx->content[ctx->offset] = 0;
	if (read_count)
	{
		*read_count = fetch_size;
	}
	if (strstr(ctx->content, "\r\n\r\n") == NULL)
	{
		if (fetch_size == 0)
		{
			return WS_ERROR_HANDSHAKE;
		}
		return WS_ERROR_OK;
	}
	for (tok = strtok(ctx->content, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n"))
	{
		if (*tok == 'H' && *(tok + 1) == 'T' && *(tok + 2) == 'T' && *(tok + 3) == 'P')
		{
			p = strchr(tok, ' ');
			p = strchr(p + 1, ' ');
			*p = '\0';
			if (strcmp(tok, "HTTP/1.1 101") != 0 && strcmp(tok, "HTTP/1.0 101") != 0)
			{
				return WS_ERROR_HANDSHAKE_BAD_STATUS_ERR;
			}
			flags |= REQUEST_VALID_STATUS;
		}
		else
		{
			p = strchr(tok, ' ');
			*p = '\0';
			if (strcmp(tok, "Upgrade:") == 0)
			{
				if (stricmp(p + 1, "websocket") == 0)
				{
					flags |= REQUEST_HAS_UPGRADE;
				}
			}
			if (strcmp(tok, "Connection:") == 0)
			{
				if (stricmp(p + 1, "upgrade") == 0)
				{
					flags |= REQUEST_HAS_CONNECTION;
				}
			}
			if (strcmp(tok, "Sec-WebSocket-Accept:") == 0)
			{
				if (strcmp(p + 1, ctx->key_hash) == 0)
				{
					flags |= REQUEST_VALID_ACCEPT;
				}
			}
		}
	}
	if (!(flags & REQUEST_HAS_UPGRADE))
	{
		return WS_ERROR_HANDSHAKE_NO_UPGRADE_ERR;
	}
	if (!(flags & REQUEST_HAS_CONNECTION))
	{
		return WS_ERROR_HANDSHAKE_NO_CONNECTION_ERR;
	}
	if (!(flags & REQUEST_VALID_ACCEPT))
	{
		return WS_ERROR_HANDSHAKE_BAD_ACCEPT_ERR;
	}
	client->flags &= ~CLIENT_CONNECTING;
	client->flags |= CLIENT_CONNECTED;
	return WS_ERROR_OK;
}

//somewhat hackish stricmp
int stricmp(const char *s1, const char *s2)
{
	register unsigned char c1, c2;
	register unsigned char flipbit = ~(1 << 5);
	do
	{
		c1 = (unsigned char)*s1++ & flipbit;
		c2 = (unsigned char)*s2++ & flipbit;
		if (c1 == '\0')
			return c1 - c2;
	} while (c1 == c2);
	return c1 - c2;
}

int libwsclient_send_fragment(wsclient *client, char *strdata, int len, int flags)
{
	struct timeval tv;
	unsigned char mask[4];
	unsigned int mask_int;
	unsigned long long payload_len;
	unsigned char finNopcode;
	unsigned int payload_len_small;
	unsigned int payload_offset = 6;
	unsigned int len_size;
	unsigned long long be_payload_len;
	unsigned int sent = 0;
	int i, sockfd;
	unsigned int frame_size;
	char *data = NULL;
	if (client->flags & CLIENT_SHOULD_CLOSE){
		libwsclient_process_error(client, WS_ERROR_SEND_AFTER_SHOULD_CLOSE, 0);
		return 0;
	}
	if (client->flags & CLIENT_SENT_CLOSE_FRAME)
	{
		libwsclient_process_error(client, WS_ERROR_SEND_AFTER_CLOSE_FRAME_ERR, 0);
		return 0;
	}
	if (client->flags & CLIENT_CONNECTING)
	{
		libwsclient_process_error(client, WS_ERROR_SEND_DURING_CONNECT_ERR, 0);
		return 0;
	}

	if (strdata == NULL)
	{
		libwsclient_process_error(client, WS_ERROR_INVALID_PARAMETER, 0);
		return 0;
	}

	gettimeofday(&tv, NULL);
	srand(tv.tv_usec * tv.tv_sec);
	mask_int = rand();
	memcpy(mask, &mask_int, 4);
	payload_len = len;
	if (payload_len <= 125)
	{
		frame_size = 6 + payload_len;
		payload_len_small = payload_len;
	}
	else if (payload_len > 125 && payload_len <= 0xffff)
	{
		frame_size = 8 + payload_len;
		payload_len_small = 126;
		payload_offset += 2;
	}
	else if (payload_len > 0xffff && payload_len <= 0xffffffffffffffffLL)
	{
		frame_size = 14 + payload_len;
		payload_len_small = 127;
		payload_offset += 8;
	}
	else
	{
		libwsclient_process_error(client, WS_ERROR_INVALID_PARAMETER, 0);
		return 0;
	}
	data = (char *)malloc(frame_size);

	memset(data, 0, frame_size);
	*data = flags & 0xff;
	*(data + 1) = payload_len_small | 0x80; //payload length with mask bit on
	if (payload_len_small == 126)
	{
		payload_len &= 0xffff;
		len_size = 2;
		for (i = 0; i < len_size; i++)
		{
			*(data + 2 + i) = *((char *)&payload_len + (len_size - i - 1));
		}
	}
	if (payload_len_small == 127)
	{
		payload_len &= 0xffffffffffffffffLL;
		len_size = 8;
		for (i = 0; i < len_size; i++)
		{
			*(data + 2 + i) = *((char *)&payload_len + (len_size - i - 1));
		}
	}
	for (i = 0; i < 4; i++)
		*(data + (payload_offset - 4) + i) = mask[i] & 0xff;

	memcpy(data + payload_offset, strdata, len);
	for (i = 0; i < len; i++)
		*(data + payload_offset + i) ^= mask[i % 4] & 0xff;
	sent = 0;
	i = 1;

	//we don't need the send lock here.  It *should* have already been acquired before sending fragmented message
	//and will be released after last fragment sent.
	while (sent < frame_size && i > 0)
	{
		i = client->write(client, data + sent, frame_size - sent);
		sent += i;
	}

	if (i < 0)
	{
		libwsclient_process_error(client, WS_ERROR_WRITE_ERROR, i);
	}

	free(data);
	return sent;
}
