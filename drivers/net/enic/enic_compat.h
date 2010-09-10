#ifndef __ENIC_COMPAT_H__
#define __ENIC_COMPAT_H__

#ifndef readq
static inline u64 readq(void __iomem *reg)
{
        return (((u64)readl(reg + 0x4UL) << 32) |
                (u64)readl(reg));
}

static inline void writeq(u64 val, void __iomem *reg)
{
        writel(val & 0xffffffff, reg);
        writel(val >> 32, reg + 0x4UL);
}
#endif

#endif
