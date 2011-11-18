#ifndef __LIBCXGBI_COMPAT_H__
#define __LIBCXGBI_COMPAT_H__

static inline int scsi_bidi_cmnd(struct scsi_cmnd *cmd)
{
	return 0;
}

static ssize_t sysfs_format_mac(char *buf, const unsigned char *addr, int len)
{
        int i;
        char *cp = buf;

        for (i = 0; i < len; i++)
                cp += sprintf(cp, "%02x%c", addr[i],
                              i == (len - 1) ? '\n' : ':');
        return cp - buf;
}


#endif
