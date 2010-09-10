/*
 * include/linux/mpage.h
 *
 * Contains declarations related to preparing and submitting BIOS which contain
 * multiple pagecache pages.
 */

/*
 * (And no, it doesn't do the #ifdef __MPAGE_H thing, and it doesn't do
 * nested includes.  Get it right in the .c file).
 */

struct mpage_data {
	struct bio *bio;
	sector_t last_block_in_bio;
	get_block_t *get_block;
	unsigned use_writepage;
};

struct writeback_control;
typedef int (writepage_t)(struct page *page, struct writeback_control *wbc);
typedef int (writepage_data_t)(struct page *page, struct writeback_control *wbc, void *data);

struct bio *mpage_bio_submit(int rw, struct bio *bio);
int mpage_readpages(struct address_space *mapping, struct list_head *pages,
				unsigned nr_pages, get_block_t get_block);
int mpage_readpage(struct page *page, get_block_t get_block);
struct bio *__mpage_writepage(struct bio *bio, struct page *page,
	get_block_t get_block, sector_t *last_block_in_bio, int *ret,
	struct writeback_control *wbc, writepage_t writepage_fn);
int __mpage_writepage_mpd(struct page *page, struct writeback_control *wbc,
                      struct mpage_data *mpd);
int mpage_writepages(struct address_space *mapping,
		struct writeback_control *wbc, get_block_t get_block);
int mpage_writepage(struct page *page, get_block_t *get_block,
		struct writeback_control *wbc);

static inline int
generic_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, NULL);
}

int
write_cache_pages(struct address_space *mapping, int range_cont,
                struct writeback_control *wbc, writepage_data_t writepage,
                void *data);
