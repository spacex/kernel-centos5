snd-hda-intel-y := hda_intel.o
# since snd-hda-intel is the only driver using hda-codec,
# merge it into a single module although it was originally
# designed to be individual modules
snd-hda-intel-y += hda_codec.o
snd-hda-intel-y += hda_hwdep.o
snd-hda-intel-$(CONFIG_PROC_FS) += hda_proc.o
snd-hda-intel-y += hda_generic.o
snd-hda-intel-y += patch_realtek.o
snd-hda-intel-y += patch_cmedia.o
snd-hda-intel-y += patch_analog.o
snd-hda-intel-y += patch_sigmatel.o
snd-hda-intel-y += patch_si3054.o
snd-hda-intel-y += patch_atihdmi.o
snd-hda-intel-y += patch_conexant.o
snd-hda-intel-y += patch_via.o

obj-$(CONFIG_SND_HDA_INTEL) += snd-hda-intel.o
