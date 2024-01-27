/*
 * Copyright (c) 2024 Kirill A. Korinsky <kirill@korins.ky>
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

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "openbsd-compat.h"
#include "opensmtpd.h"
#include "mheader.h"

struct admd_message {
	int foundmatch;
	int err;
	int inheader;
	int parsing_headers;
	char **cache;
	size_t cachelen;
	size_t headerlen;
};

void usage(void);
void admd_conf(const char *, const char *);
void *admd_message_new(struct osmtpd_ctx *);
void admd_message_free(struct osmtpd_ctx *, void *);
void admd_dataline(struct osmtpd_ctx *, const char *);
void admd_commit(struct osmtpd_ctx *);
void admd_err(struct admd_message *, const char *);
void admd_cache(struct admd_message *, const char *);
const char *admd_authservid(struct admd_message *);
void admd_freecache(struct admd_message *);

char *authservid;
int reject = 0;
int spam = 0;
int verbose = 0;

int
main(int argc, char *argv[])
{
	int ch;

	if (pledge("stdio", NULL) == -1)
		osmtpd_err(1, "pledge");

	while ((ch = getopt(argc, argv, "rvs")) != -1) {
		switch (ch) {
		case 'r':
			reject = 1;
			break;
		case 's':
			spam = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc > 1)
		osmtpd_errx(1, "invalid authservid count");
	if (argc == 1)
		authservid = argv[0];

	osmtpd_local_message(admd_message_new, admd_message_free);
	osmtpd_register_filter_dataline(admd_dataline);
	osmtpd_register_filter_commit(admd_commit);
	osmtpd_register_conf(admd_conf);
	osmtpd_run();

	return 0;
}

void
admd_conf(const char *key, const char *value)
{
	if (key == NULL) {
		if (authservid == NULL)
			osmtpd_errx(1, "Didn't receive admd config option");
		return;
	}
	if (strcmp(key, "admd") == 0 && authservid == NULL) {
		if ((authservid = strdup(value)) == NULL)
			osmtpd_err(1, "malloc");
	}
}

void *
admd_message_new(struct osmtpd_ctx *ctx)
{
	struct admd_message *msg;

	if ((msg = malloc(sizeof(*msg))) == NULL)
		osmtpd_err(1, "malloc");

	msg->foundmatch = 0;
	msg->err = 0;
	msg->inheader = 0;
	msg->parsing_headers = 1;
	msg->cache = NULL;
	msg->cachelen = 0;
	msg->headerlen = 0;

	return msg;
}

void
admd_message_free(struct osmtpd_ctx *ctx, void *data)
{
	struct admd_message *msg = data;

	admd_freecache(msg);
	free(msg);
}

void
admd_dataline(struct osmtpd_ctx *ctx, const char *orig)
{
	struct admd_message *msg = ctx->local_message;
	const char *line = orig;
	const char *msgauthid;
	size_t i;

	if (msg->err) {
		if (line[0] == '.' && line[1] =='\0')
			osmtpd_filter_dataline(ctx, ".");
		return;
	}
		
	if (line[0] == '\0')
		msg->parsing_headers = 0;
	if (line[0] == '.')
		line++;
	if (msg->parsing_headers) {
		if (line[0] != ' ' && line[0] != '\t') {
			if (msg->inheader) {
				msgauthid = admd_authservid(msg);
				if (msgauthid == NULL && errno != EINVAL)
					return;
				if (msgauthid != NULL &&
				    strcmp(msgauthid, authservid) == 0)
					msg->foundmatch = 1;
				else {
					for (i = 0; i < msg->cachelen; i++)
						osmtpd_filter_dataline(ctx,
						    "%s", msg->cache[i]);
				}
				admd_freecache(msg);
			}
			msg->inheader = 0;
		}
		if (strncasecmp(line, "Authentication-Results", 22) == 0) {
			line += 22;
			while (line[0] == ' ' || line[0] == '\t')
				line++;
			if (line++[0] == ':') {
				msg->inheader = 1;
				admd_cache(msg, orig);
				return;
			}
		} else if (msg->inheader &&
		    (line[0] == ' ' || line[0] == '\t')) {
			admd_cache(msg, orig);
			return;
		} else if (spam && strncasecmp(line, "X-Spam", 6) == 0) {
			line += 22;
			while (line[0] == ' ' || line[0] == '\t')
				line++;
			if (line++[0] == ':') {
				return;
			}
		}
	}

	osmtpd_filter_dataline(ctx, "%s", orig);
	return;
}

void
admd_commit(struct osmtpd_ctx *ctx)
{
	struct admd_message *msg = ctx->local_message;

	if (msg->err) {
		osmtpd_filter_disconnect(ctx, "Internal server error");
		return;
	}
	if (reject && msg->foundmatch) {
		osmtpd_filter_disconnect(ctx, "Message contains "
		    "Authentication-Results header for authserv-id '%s'",
		    authservid);
		fprintf(stderr, "%016"PRIx64" Message contains "
		    "Authentication-Results header for authserv-id '%s': "
		    "rejected\n", ctx->reqid, authservid);
		return;
	}

	osmtpd_filter_proceed(ctx);
	if (msg->foundmatch) {
		fprintf(stderr, "%016"PRIx64" Message contains "
		    "Authentication-Results header for authserv-id '%s': "
		    "filtered\n", ctx->reqid, authservid);
	} else if (verbose)
		fprintf(stderr, "%016"PRIx64" Message contains no "
		   "Authentication-Results header for authserv-id '%s'\n",
		    ctx->reqid, authservid);
}

void
admd_err(struct admd_message *message, const char *msg)
{
	message->err = 1;
	fprintf(stderr, "%s: %s\n", msg, strerror(errno));
}

void
admd_cache(struct admd_message *msg, const char *line)
{
	char **tcache;

	if ((tcache = reallocarray(msg->cache, msg->cachelen + 1,
	    sizeof(*(msg->cache)))) == NULL) {
		admd_freecache(msg);
		admd_err(msg, "malloc");
	}
	msg->cache = tcache;
	msg->cache[msg->cachelen] = strdup(line);
	if (msg->cache[msg->cachelen] == NULL) {
		admd_freecache(msg);
		admd_err(msg, "strdup");
	}
	msg->cachelen++;
	msg->headerlen += strlen(line[0] == '.' ? line + 1 : line);
	return;
}

const char *
admd_authservid(struct admd_message *msg)
{
	char *header0, *header, *line, *end;
	size_t headerlen;
	size_t i = 0;
	
	headerlen = msg->headerlen + (msg->cachelen * 2) + 1;
	header0 = header = malloc(headerlen);
	if (header == NULL) {
		admd_err(msg, "malloc");
		return NULL;
	}
	header[0] = '\0';
	for (i = 0; i < msg->cachelen; i++) {
		line = msg->cache[i];
		if (line[0] == '.')
			line++;
		if (strlcat(header, line, headerlen) >= headerlen ||
		    strlcat(header, "\r\n", headerlen) >= headerlen) {
			osmtpd_errx(1, "miscalculated header\n");
			exit(1);
		}
	}

	/* Skip key */
	header += 22;
	while (header[0] == ' ' || header[0] == '\t')
		header++;
	/* : */
	header++;

	header = osmtpd_mheader_skip_cfws(header, 1);

	if ((end = osmtpd_mheader_skip_value(header, 0)) == NULL) {
		errno = EINVAL;
		free(header0);
		return NULL;
	}
	memmove(header0, header, end - header);
	header0[end - header] = '\0';

	return header0;
}

void
admd_freecache(struct admd_message *msg)
{
	while (msg->cachelen > 0) {
		msg->cachelen--;
		free(msg->cache[msg->cachelen]);
	}
	free(msg->cache);
	msg->cache = NULL;
	msg->cachelen = 0;
	msg->headerlen = 0;
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: filter-admdscrub [-rvs] [authserv-id]\n");
	exit(1);
}
