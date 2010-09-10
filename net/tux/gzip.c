/*	$Id: zlib.h,v 1.2 1997/12/23 10:47:44 paulus Exp $	*/

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/zlib.h>
#include <net/tux.h>

#define STREAM_END_SPACE 12

int tux_gzip_compress (tux_req_t *req, unsigned char *data_in, unsigned char *data_out, __u32 *in_len, __u32 *out_len)
{
	z_stream *s = &req->ti->gzip_state;
	int ret, left;

	down(&req->ti->gzip_sem);
	if (zlib_deflateReset(s) != Z_OK)
		BUG();

	s->next_in = data_in;
	s->next_out = data_out;
	s->avail_in = *in_len;
	s->avail_out = *out_len;

	Dprintk("calling zlib_deflate with avail_in %d, avail_out %d\n", s->avail_in, s->avail_out);
	ret = zlib_deflate(s, Z_FINISH);
	Dprintk("deflate returned with avail_in %d, avail_out %d, total_in %ld, total_out %ld\n", s->avail_in, s->avail_out, s->total_in, s->total_out);

	if (ret != Z_STREAM_END) {
		printk("bad: deflate returned with %d! avail_in %d, avail_out %d, total_in %ld, total_out %ld\n", ret, s->avail_in, s->avail_out, s->total_in, s->total_out);
		BUG();
	}
	*in_len = s->avail_in;
	*out_len = s->avail_out;
	left = s->avail_in;

	up(&req->ti->gzip_sem);

	return left;
}

