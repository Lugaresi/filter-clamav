/*
 * Copyright (c) 2019 Martijn van Duren <martijn@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <limits.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <opensmtpd.h>
#include <unistd.h>

struct clamav_message {
	FILE *cm_ofile;
	int cm_clamfd;
	struct event cm_rev;
	int cm_err;
	int cm_reject;
};

int mark = 0;
int verbose = 0;
char *address = "127.0.0.1:3310";

void clamav_dataline(struct osmtpd_ctx *, const char *);
void clamav_commit(struct osmtpd_ctx *);
void *clamav_message_new(struct osmtpd_ctx *);
void clamav_message_free(struct osmtpd_ctx *, void *);
void clamav_finalize(int, short, void *);
int clamav_connect(struct clamav_message *);
void clamav_err(struct clamav_message *, const char *, ...);
void clamav_errx(struct clamav_message *, const char *, ...);
void usage(void);

int
main(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "ms:v")) != -1) {
		switch (ch) {
		case 'm':
			mark = 1;
			break;
		case 's':
			address = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
		}
	}

	osmtpd_local_message(clamav_message_new, clamav_message_free);
	osmtpd_register_filter_dataline(clamav_dataline);
	osmtpd_register_filter_commit(clamav_commit);
	osmtpd_run();

	return 0;
}

void
clamav_dataline(struct osmtpd_ctx *ctx, const char *line)
{
	struct clamav_message *message = ctx->local_message;
	struct msghdr msg;
	struct iovec iov;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr* cmsg;

	if (!(line[0] == '.' && line[1] == '\0')) {
		if (line[0] == '.')
			line++;
		fprintf(message->cm_ofile, "%s\r\n", line);
		return;
	}

	fflush(message->cm_ofile);
	if (verbose)
		warnx("Scanning message: %llx", ctx->reqid);
	if ((message->cm_clamfd = clamav_connect(message)) == -1)
		return;

	event_set(&(message->cm_rev), message->cm_clamfd, EV_READ,
	    clamav_finalize, ctx);
	event_add(&(message->cm_rev), NULL);

	iov.iov_base = "zFILDES\0";
	iov.iov_len = sizeof("zFILDES\0");
	bzero(&msg, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*(int*) CMSG_DATA(cmsg) = fileno(message->cm_ofile);

	if (sendmsg(message->cm_clamfd, &msg, 0) == -1) {
		clamav_errx(message, "Could not send mail to clamav");
		return;
	}
}

void
clamav_commit(struct osmtpd_ctx *ctx)
{
	struct clamav_message *message = ctx->local_message;

	if (message->cm_err)
		osmtpd_filter_disconnect(ctx, "Internal server error");
	else if (message->cm_reject && !mark)
		osmtpd_filter_reject(ctx, 450, "Virus detected");
	else
		osmtpd_filter_proceed(ctx);
}

void *
clamav_message_new(struct osmtpd_ctx *ctx)
{
	struct clamav_message *message;

	if ((message = calloc(1, sizeof(*message))) == NULL)
		return NULL;

	if ((message->cm_ofile = tmpfile()) == NULL) {
		free(message);
		return NULL;
	}

	return message;
}

void
clamav_message_free(struct osmtpd_ctx *ctx, void *data)
{
	struct clamav_message *message = data;

	fclose(message->cm_ofile);
	free(message);
}

void
clamav_finalize(int fd, short event, void *cookie)
{
	struct osmtpd_ctx *ctx = cookie;
	struct clamav_message *message = ctx->local_message;
	char buf[1024], *response, *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	int ret;

	if ((ret = read(message->cm_clamfd, buf, sizeof(buf))) == -1) {
		clamav_err(message, "Failed to read clamav response");
		goto roundup;
	}

	buf[ret] = '\0';

	if ((response = strchr(buf, ':')) == NULL) {
		clamav_errx(message, "Received invalid response from clamav");
		goto roundup;
	}

	do {
		response++;
	} while (isspace(response[0]));

	if (strcmp(response, "OK") != 0) {
		message->cm_reject = 1;
		osmtpd_filter_dataline(ctx, "X-Spam: yes");
		osmtpd_filter_dataline(ctx, "X-Spam-clamav: %s", response);
	}

roundup:
	rewind(message->cm_ofile);
	while ((linelen = getline(&line, &linesize, message->cm_ofile)) != -1) {
		line[linelen - 1] = '\0';
		osmtpd_filter_dataline(ctx, "%s", line);
	}
	if (ferror(message->cm_ofile))
		clamav_errx(message, "Couldn't copy tempfile back");
	osmtpd_filter_dataline(ctx, ".");

}

int
clamav_connect(struct clamav_message *message)
{
	struct addrinfo ai, *res, *res0;
	struct sockaddr_un sun;
	struct sockaddr *sa;
	char buf[PATH_MAX];
	char *host = buf, *port;
	int gacode;
	int fd;

	if (strlcpy(buf, address, sizeof(buf)) >= sizeof(buf))
		osmtpd_errx(1, "-s address too long");

	switch (address[0]) {
	case '/':
		sa = (struct sockaddr *)&sun;
		sun.sun_family = AF_UNIX;
		sun.sun_len = sizeof(sun);
		if (strlcpy(sun.sun_path, address,
		    sizeof(sun.sun_path)) >= sizeof(sun.sun_path))
			osmtpd_errx(1, "-s address too long");
		if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
			clamav_err(message, "Could not create socket");
			return -1;
		}
		if (connect(fd, sa, sizeof(sun)) == -1) {
			clamav_err(message, "Could not connect to %s", address);
			return -1;
		}
		break;
	default:
		if ((port = strchr(host, ':')) == NULL)
			port = "3310";
		else {
			port[0] = '\0';
			port++;
		}
		ai.ai_family = AF_UNSPEC;
		ai.ai_socktype = SOCK_STREAM;
		ai.ai_protocol=IPPROTO_TCP;
		if ((gacode = getaddrinfo(host, port, &ai, &res0)) == -1) {
			clamav_errx(message, "Could not connect to %s: %s",
			    address, gai_strerror(gacode));
			return -1;
		}
		for (res = res0; res != NULL; res = res->ai_next) {
			if ((fd = socket(res->ai_family, res->ai_socktype,
			    res->ai_protocol)) == -1) {
				clamav_err(message, "Could not create socket");
				return -1;
			}
			if (connect(fd, res->ai_addr, res->ai_addrlen) == 0)
				break;
			/* TODO maybe show which resolved host */
			warn("Could not connect %s", address);
			close(fd);
		}
		if (res == NULL) {
			clamav_errx(message, "Could not connect to any host");
			return -1;
		}
		break;
	}
	return fd;
}

void
clamav_err(struct clamav_message *message, const char *fmt, ...)
{
	va_list ap;
	int serrno = errno;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "%s\n", strerror(serrno));

	message->cm_err = 1;
}

void
clamav_errx(struct clamav_message *message, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	message->cm_err = 1;
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: filter-clamav [-mv] [-s address]\n");
	exit(1);
}
