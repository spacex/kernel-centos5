#ifndef _LINUX_SETUP_H
#define _LINUX_SETUP_H */

static inline void __cpuinit amd_enable_pci_ext_cfg(struct cpuinfo_x86 *c)
{
	u64 reg;
	rdmsrl(MSR_K8_NB_CFG, reg);
	if (!(reg & ENABLE_CF8_EXT_CFG)) {
		reg |= ENABLE_CF8_EXT_CFG;
		wrmsrl(MSR_K8_NB_CFG, reg);
	}
	set_bit(X86_FEATURE_PCI_EXT_CFG, &c->x86_capability);
}

#endif  /* _LINUX_SETUP_H */

