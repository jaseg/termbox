struct bytebuffer {
	char *buf;
	int len;
	int cap;
	int alloc_error;
};

static int bytebuffer_reserve(struct bytebuffer *b, int cap) {
	if (b->cap >= cap)
		return b->alloc_error;

	// prefer doubling capacity
	if (b->cap * 2 >= cap)
		cap = b->cap * 2;

	char *newbuf = realloc(b->buf, cap);
	if(!newbuf){
		b->alloc_error = 1;
		return 1;
	}
	b->buf = newbuf;
	b->cap = cap;
	return b->alloc_error;
}

static int bytebuffer_init(struct bytebuffer *b, int cap) {
	b->cap = 0;
	b->len = 0;
	b->buf = 0;
	b->alloc_error = 0;
	return bytebuffer_reserve(b, cap);
}

static void bytebuffer_free(struct bytebuffer *b) {
	if (b->buf)
		free(b->buf);
}

static void bytebuffer_clear(struct bytebuffer *b) {
	b->len = 0;
}

static int bytebuffer_append(struct bytebuffer *b, const char *data, int len) {
	if(bytebuffer_reserve(b, b->len + len))
		return 1;
	memcpy(b->buf + b->len, data, len);
	b->len += len;
	return 0;
}

static int bytebuffer_puts(struct bytebuffer *b, const char *str) {
	return bytebuffer_append(b, str, strlen(str));
}

static int bytebuffer_resize(struct bytebuffer *b, int len) {
	if(bytebuffer_reserve(b, len))
		return 1;
	b->len = len;
	return 0;
}

static void bytebuffer_flush(struct bytebuffer *b, int fd) {
	write(fd, b->buf, b->len);
	bytebuffer_clear(b);
}

static void bytebuffer_truncate(struct bytebuffer *b, int n) {
	if (n <= 0)
		return;
	if (n > b->len)
		n = b->len;
	const int nmove = b->len - n;
	memmove(b->buf, b->buf+n, nmove);
	b->len -= n;
}
