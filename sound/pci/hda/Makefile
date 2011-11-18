snd-hda-intel-y := hda_intel.o
# RHEL5 uses only one big module
snd-hda-intel-y += hda_codec.o
snd-hda-intel-y += hda_eld.o
snd-hda-intel-y += hda_hwdep.o
snd-hda-intel-y += hda_beep.o
snd-hda-intel-$(CONFIG_PROC_FS) += hda_proc.o
snd-hda-intel-y += hda_generic.o
snd-hda-intel-y += patch_realtek.o
snd-hda-intel-y += patch_cmedia.o
snd-hda-intel-y += patch_analog.o
snd-hda-intel-y += patch_sigmatel.o
snd-hda-intel-y += patch_si3054.o
snd-hda-intel-y += patch_hdmi.o
snd-hda-intel-y += patch_conexant.o
snd-hda-intel-y += patch_via.o
snd-hda-intel-y += patch_ca0110.o
snd-hda-intel-y += patch_cirrus.o

obj-$(CONFIG_SND_HDA_INTEL) += snd-hda-intel.o
