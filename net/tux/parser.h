/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, Ingo Molnar <mingo@redhat.com>
 *
 * parser.h: generic parsing routines
 */

#define get_c(ptr,left)						\
({								\
	char __ret;					\
								\
	if (!left)						\
		GOTO_INCOMPLETE;				\
	left--;							\
	__ret = *((ptr)++);					\
	if (!__ret)						\
		GOTO_REDIR;					\
	__ret;							\
})

#define PARSE_TOKEN(ptr,str,left)				\
	({							\
		int __ret;					\
								\
		if (!left)					\
			GOTO_INCOMPLETE;			\
		if (sizeof(str)-1 > left) {			\
			if (memcmp(ptr, str, left))		\
				GOTO_REDIR;			\
			GOTO_INCOMPLETE;			\
		}						\
								\
		if (memcmp(ptr, str, sizeof(str)-1))		\
			__ret = 0;				\
		else {						\
			ptr += sizeof(str)-1;			\
			left -= sizeof(str)-1;			\
			__ret = 1;				\
		}						\
		__ret;						\
	})

#define PARSE_METHOD(req,ptr,name,left)				\
	({							\
		int __ret;					\
								\
		if (PARSE_TOKEN(ptr,#name" ",left)) {		\
			req->method = METHOD_##name;		\
			__ret = 1;				\
		} else						\
			__ret = 0;				\
		__ret;						\
	})

#define COPY_LINE(ptr,target,left)				\
	do {							\
		char prev_c = 0, c;				\
		while (((c = get_c(ptr,left))) != '\n')	\
			*target++ = prev_c = c;			\
		if (prev_c != '\r')				\
			GOTO_REDIR;				\
	} while (0)

#define COPY_LINE_TOLOWER(ptr,target,left,limit)		\
	do {							\
		char prev_c = 0, c;				\
		while (((c = get_c(ptr,left))) != '\n') {	\
			if ((c >= 'A') && (c <= 'Z'))		\
				c -= 'A'-'a';			\
			*target++ = prev_c = c;			\
			if (target == (limit))			\
				GOTO_REDIR;			\
		}						\
		if (prev_c != '\r')				\
			GOTO_REDIR;				\
	} while (0)

#define COPY_FIELD(ptr,target,left)				\
	do {							\
		char c;						\
		while ((c = get_c(ptr,left)) != ' ')		\
			*target++ = c;				\
	} while (0)

#define SKIP_LINE(ptr,left)					\
	do {							\
		char prev_c = 0, c;				\
		while (((c = get_c(ptr,left))) != '\n')		\
			prev_c = c;				\
		if (prev_c != '\r')				\
			GOTO_REDIR;				\
	} while (0)

#define SKIP_WHITESPACE(curr,left)		\
do {						\
	while ((left) && (*(curr) == ' '))	\
		(curr)++, (left)--;		\
	if (!(left))				\
		GOTO_REDIR;			\
} while (0)

