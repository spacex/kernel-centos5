#ifndef LINUX_MSI_H
#define LINUX_MSI_H

struct msi_msg {
        u32     address_lo;     /* low 32 bits of msi message address */
        u32     address_hi;     /* high 32 bits of msi message address */
        u32     data;           /* 16 bits of msi message data */
};

struct msi_desc {
	struct {
		__u8	type	: 5; 	/* {0: unused, 5h:MSI, 11h:MSI-X} */
		__u8	maskbit	: 1; 	/* mask-pending bit supported ?   */
		__u8	state	: 1; 	/* {0: free, 1: busy}		  */
		__u8	reserved: 1; 	/* reserved			  */
		__u8	entry_nr;    	/* specific enabled entry 	  */
		__u8	default_vector; /* default pre-assigned vector    */
		__u8	unused; 	/* formerly unused destination cpu*/
	}msi_attrib;

	struct {
		__u16	head;
		__u16	tail;
	}link;

	void __iomem *mask_base;
	struct pci_dev *dev;

#ifdef CONFIG_PM
        /* PM save area for MSIX address/data */

	u32	address_hi_save;
	u32	address_lo_save;
	u32	data_save;
#endif
};

extern struct msi_desc* msi_desc[];
#endif /* LINUX_MSI_H */
