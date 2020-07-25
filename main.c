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

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "opensmtpd.h"

struct admd_message {
	int foundmatch;
	int err;
	int inheader;
	int parsing_headers;
	char **cache;
	size_t cachelen;
};

void usage(void);
void *admd_message_new(struct osmtpd_ctx *);
void admd_message_free(struct osmtpd_ctx *, void *);
void admd_dataline(struct osmtpd_ctx *, const char *);
void admd_commit(struct osmtpd_ctx *);
void admd_err(struct admd_message *, const char *);
void admd_cache(struct admd_message *, const char *);
const char *admd_authservid(struct admd_message *);
void admd_freecache(struct admd_message *);

char authservid[256] = "";
int reject = 0;
int verbose = 0;

int
main(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "a:rv")) != -1) {
		switch (ch) {
		case 'a':
			if (strlcpy(authservid, optarg, sizeof(authservid)) >=
			    sizeof(authservid))
				osmtpd_errx(1, "authserv-id is too long");
			break;
		case 'r':
			reject = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

	if (pledge("stdio", NULL) == -1)
		osmtpd_err(1, "pledge");

	if (authservid[0] == '\0') {
		if (gethostname(authservid, sizeof(authservid)) == -1)
			osmtpd_err(1, "gethostname");
	}
	if (strchr(authservid, '\r') != NULL ||
	    strchr(authservid, '\n') != NULL)
		osmtpd_errx(1, "ubsupported character in authserv-id");

	osmtpd_local_message(admd_message_new, admd_message_free);
	osmtpd_register_filter_dataline(admd_dataline);
	osmtpd_register_filter_commit(admd_commit);
	osmtpd_run();

	return 0;
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
				if (strcmp(msgauthid, authservid) == 0)
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
		if (strncmp(line, "Authentication-Results:", 23) == 0) {
			msg->inheader = 1;
			admd_cache(msg, orig);
			return;
		}
		if (msg->inheader && (line[0] == ' ' || line[0] == '\t')) {
			admd_cache(msg, orig);
			return;
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
	return;
}

const char *
admd_authservid(struct admd_message *msg)
{
	static char msgauthid[sizeof(authservid)];
	const char *header;
	size_t i = 0;
	int depth = 0;
	
	msgauthid[0] = '\0';

	header = msg->cache[0];

	if (header[0] == '.')
		header++;

	/* Skip key */
	header += 23;

	/* CFWS */
	/*
	 * Take the extremely loose approach with both FWS and comment so we
	 * might match a non fully complient comment and still get the right
	 * authserv-id
	 */
fws:
	while (header[0] == ' ' || header[0] == '\t')
		header++;
	if (header[0] == '\0') {
		if (++i >= msg->cachelen)
			return msgauthid;
		header = msg->cache[i];
		/* For leniency allow multiple consequtive FWS */
		goto fws;
	}
	/* comment */
	if (header[0] == '(') {
		depth++;
		header++;
	}
	if (depth > 0) {
		while (1) {
			/*
			 * consume a full quoted-pair, which may contain
			 * parentheses
			 */
			if (header[0] == '"') {
				header++;
				while (header[0] != '"') {
					if (header[0] == '\\')
						header++;
					if (header[0] == '\0') {
						if (++i >= msg->cachelen) {
							return msgauthid;
						}
						header = msg->cache[i];
					} else
						header++;
				}
				header++;
			/* End of comment */
			} else if (header[0] == ')') {
				header++;
				if (--depth == 0)
					goto fws;
			} else if (header[0] == '(') {
				header++;
				depth++;
			} else if (header[0] == '\0') {
				if (++i >= msg->cachelen)
					return msgauthid;
				header = msg->cache[i];
			} else
				header++;
		}
	}
	/* Quoted-string */
	if (header[0] == '"') {
		header++;
		for (i = 0; header[0] != '"' && header[0] != '\0' &&
		    i < sizeof(msgauthid); i++, header++) {
			if (header[0] == '\\')
				header++;
			/* Don't do Newline at all */
			if (header[0] == '\0') {
				i = 0;
				break;
			}
			msgauthid[i] = header[0];
		}
	/* token */
	} else {
		/*
		 * Be more lenient towards token to hit more
		 * edgecases
		 */
		for (i = 0; header[i] != ' ' && header[i] != '\t' &&
		    header[i] != ';' && header[i] != '\0' &&
		    i < sizeof(msgauthid); i++)
			msgauthid[i] = header[i];
	}
	/* If we overflow we simply don't match */
	if (i == sizeof(msgauthid))
		i = 0;
	msgauthid[i] = '\0';
	return msgauthid;
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
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: filter-admdscrub [-rv] [-a authserv-id]\n");
	exit(1);
}
