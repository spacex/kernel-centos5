#ifndef __FORCEDETH_COMPAT_H__
#define __FORCEDETH_COMPAT_H__

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_BUF_SIZE 18
#define DECLARE_MAC_BUF(var) char var[MAC_BUF_SIZE]
static inline char *print_mac(char *buf, const unsigned char *addr)
{
	sprintf(buf, MAC_FMT,
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return buf;
}

#define netif_addr_lock(dev)
#define netif_addr_unlock(dev)

#endif /* __FORCEDETH_COMPAT_H__ */
