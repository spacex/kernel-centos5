/* Get the upper 32bit of the given dma_addr_t
 * Compiler should optimize and eliminate the code if dma_addr_t is 32bit
 */
#define upper_32bit(addr) (sizeof(addr) > 4 ? (u32)((addr) >> 32) : (u32)0)

static inline u64 get_unaligned_le64(const unsigned char *addr)
{
        return (u64)addr[0] |
                ((u64)addr[1] << 8) |
                ((u64)addr[2] << 16) | 
                ((u64)addr[3] << 24) | 
                ((u64)addr[4] << 32) | 
                ((u64)addr[5] << 40) | 
                ((u64)addr[6] << 48) | 
                ((u64)addr[7] << 56);
}

static inline u16 get_unaligned_le16(const unsigned char *addr)
{
        return addr[0] | (addr[1] << 8);
}

static inline char *kstrndup(const char *s, size_t max, gfp_t gfp)
{
        size_t len;
        char *buf;

        if (!s)
                return NULL;

        len = strnlen(s, max);
        buf = kmalloc_track_caller(len+1, gfp);
        if (buf) {
                memcpy(buf, s, len);
                buf[len] = '\0';
        }
        return buf;
}

/* Realtek codecs */
extern struct hda_codec_preset_list realtek_list[];
/* C-Media codecs */
extern struct hda_codec_preset_list cmedia_list[];
/* Analog Devices codecs */
extern struct hda_codec_preset_list analog_list[];
/* SigmaTel codecs */
extern struct hda_codec_preset_list sigmatel_list[];
/* SiLabs 3054/3055 modem codecs */
extern struct hda_codec_preset_list si3054_list[];
/* ATI HDMI codecs */
extern struct hda_codec_preset_list atihdmi_list[];
/* INTEL HDMI codecs */
extern struct hda_codec_preset_list intel_list[];
/* NVIDIA HDMI codecs */
extern struct hda_codec_preset_list nvhdmi_list[];
/* Conexant audio codec */
extern struct hda_codec_preset_list conexant_list[];
/* VIA codecs */
extern struct hda_codec_preset_list via_list[];

#ifdef PRESETS
static struct hda_codec_preset_list *hda_preset_table[] = {
        realtek_list,
        cmedia_list,
        analog_list,
        sigmatel_list,
        si3054_list,
        atihdmi_list,
        intel_list,
        conexant_list,
        via_list,
        NULL
};

static void hda_register_presets(void)
{
        struct hda_codec_preset_list **preset;
        for (preset = hda_preset_table; *preset != NULL; preset++)
                snd_hda_add_codec_preset(*preset);
}

static void hda_deregister_presets(void)
{
        struct hda_codec_preset_list **preset;
        for (preset = hda_preset_table; *preset != NULL; preset++)
                snd_hda_delete_codec_preset(*preset);
}
#endif
