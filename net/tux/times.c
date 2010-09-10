/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * times.c: time conversion routines.
 *
 * Original time convserion code Copyright (C) 1999 by Arjan van de Ven
 */

/****************************************************************
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2, or (at your option)
 *	any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************/

#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ctype.h>

#define EPOCH_YEAR	1970
#define DAY		(24 * 60 * 60)
#define YEAR		(365 * DAY)
#define LEAP_YEAR	(YEAR + DAY)
#define FOUR_CYCLE	(3 * YEAR + LEAP_YEAR)

char *dayName[7] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static char *monthName[12] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

unsigned int month_table[2][12] = {
        { 31 * DAY,
	  (31 + 28) * DAY,
	  (31 + 28 + 31) * DAY,
	  (31 + 28 + 31 + 30) * DAY,
	  (31 + 28 + 31 + 30 + 31) * DAY,
	  (31 + 28 + 31 + 30 + 31 + 30) * DAY,
	  (31 + 28 + 31 + 30 + 31 + 30 + 31) * DAY,
	  (31 + 28 + 31 + 30 + 31 + 30 + 31 + 31) * DAY,
	  (31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30) * DAY,
	  (31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31) * DAY,
	  (31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30) * DAY,
	  (31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31) * DAY },
        { 31 * DAY,
	  (31 + 29) * DAY,
	  (31 + 29 + 31) * DAY,
	  (31 + 29 + 31 + 30) * DAY,
	  (31 + 29 + 31 + 30 + 31) * DAY,
	  (31 + 29 + 31 + 30 + 31 + 30) * DAY,
	  (31 + 29 + 31 + 30 + 31 + 30 + 31) * DAY,
	  (31 + 29 + 31 + 30 + 31 + 30 + 31 + 31) * DAY,
	  (31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30) * DAY,
	  (31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31) * DAY,
	  (31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30) * DAY,
	  (31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31) * DAY },
};

char itoa_h[60]={'0','0','0','0','0','0','0','0','0','0',
		 '1','1','1','1','1','1','1','1','1','1',
		 '2','2','2','2','2','2','2','2','2','2',
		 '3','3','3','3','3','3','3','3','3','3',
		 '4','4','4','4','4','4','4','4','4','4',
		 '5','5','5','5','5','5','5','5','5','5'};

char itoa_l[60]={'0','1','2','3','4','5','6','7','8','9',
		 '0','1','2','3','4','5','6','7','8','9',
		 '0','1','2','3','4','5','6','7','8','9',
		 '0','1','2','3','4','5','6','7','8','9',
		 '0','1','2','3','4','5','6','7','8','9',
		 '0','1','2','3','4','5','6','7','8','9'};

int time_unix2ls(time_t zulu, char *buf)
{
	unsigned int i, year, month, day, hour, minute, leap_year, cycles, *mtp;
	unsigned long offset;
	time_t delta;

	if ((unsigned long)zulu > (unsigned long)xtime.tv_sec)
		zulu = xtime.tv_sec;

	offset = (unsigned long)zulu;

	/* calculate the year */
	offset += YEAR + LEAP_YEAR;
	year = EPOCH_YEAR - 2;
	cycles = offset / FOUR_CYCLE;
	offset -= cycles * FOUR_CYCLE;
	year += 4 * cycles;
	if (offset >= LEAP_YEAR) {
		offset -= LEAP_YEAR;
		i = offset / YEAR;
		offset -= i * YEAR;
		year += i + 1;
		leap_year = 0;
	} else
		leap_year = 1;

	/* next we calculate the month */
	mtp = &month_table[leap_year][0];
	for (i = 0; i < 11; i++, mtp++) {
		if (offset < *mtp)
			break;
	}
	month = i;
	if (month != 0)
		offset -= *(mtp - 1);

	/* finally, calculate day, hour, minute */
	day = offset / DAY;
	offset -= day * DAY;
	hour = offset / 3600;
	offset -= hour * 3600;
	minute = offset / 60;

	/* Format:  Day, 01 Mon 1999 01:01:01 GMT */
	delta = xtime.tv_sec - zulu;
	if (delta > YEAR / 2)
		//               "May 23   2000"
		return sprintf( buf, "%s %02i  %04i", monthName[month], day + 1, year);
	else
		//                "May 23 10:14"
		return sprintf( buf, "%s %02i %02i:%02i",
			monthName[month], day + 1, hour, minute);
}

// writes the full http date, corresponding to time_t received

void last_mod_time(char * curr, const time_t t)
{
	int day, tod, year, wday, mon, hour, min, sec;

	tod = t % 86400;
	day = t / 86400;
	if (tod < 0) {
		tod += 86400;
		--day;
	}

	hour = tod / 3600;
	tod %= 3600;
	min = tod / 60;
	sec = tod % 60;

	wday = (day + 4) % 7;
	if (wday < 0)
		wday += 7;

	day -= 11017;
	/* day 0 is march 1, 2000 */
	year = 5 + day / 146097;
	day = day % 146097;
	if (day < 0) {
		day += 146097;
		--year;
	}
	/* from now on, day is nonnegative */
	year *= 4;
	if (day == 146096) {
		year += 3;
		day = 36524;
	} else {
		year += day / 36524;
		day %= 36524;
	}
	year *= 25;
	year += day / 1461;
	day %= 1461;
	year *= 4;
	if (day == 1460) {
		year += 3;
		day = 365;
	} else {
		year += day / 365;
		day %= 365;
	}

	day *= 10;
	mon = (day + 5) / 306;
	day = day + 5 - 306 * mon;
	day /= 10;
	if (mon >= 10) {
		++year;
		mon -= 10;
	} else
		mon += 2;

	sprintf(curr, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT", dayName[wday],
		day+1, monthName[mon], year, hour, min, sec);
}

// writes the full date in ISO8601 format,
// corresponding to time_t received
// example: 20011126224910

int mdtm_time(char * curr, const time_t t)
{
	int day, tod, year, wday, mon, hour, min, sec;

	tod = t % 86400;
	day = t / 86400;
	if (tod < 0) {
		tod += 86400;
		--day;
	}

	hour = tod / 3600;
	tod %= 3600;
	min = tod / 60;
	sec = tod % 60;

	wday = (day + 4) % 7;
	if (wday < 0)
		wday += 7;

	day -= 11017;
	/* day 0 is march 1, 2000 */
	year = 5 + day / 146097;
	day = day % 146097;
	if (day < 0) {
		day += 146097;
		--year;
	}
	/* from now on, day is nonnegative */
	year *= 4;
	if (day == 146096) {
		year += 3;
		day = 36524;
	} else {
		year += day / 36524;
		day %= 36524;
	}
	year *= 25;
	year += day / 1461;
	day %= 1461;
	year *= 4;
	if (day == 1460) {
		year += 3;
		day = 365;
	} else {
		year += day / 365;
		day %= 365;
	}

	day *= 10;
	mon = (day + 5) / 306;
	day = day + 5 - 306 * mon;
	day /= 10;
	if (mon >= 10) {
		++year;
		mon -= 10;
	} else
		mon += 2;

	return sprintf(curr, "213 %.4d%.2d%.2d%.2d%.2d%.2d\r\n",
		year, mon+1, day+1, hour, min, sec);
}

static inline int make_num(const char *s)
{
	if (*s >= '0' && *s <= '9')
		return 10 * (*s - '0') + *(s + 1) - '0';
	else
		return *(s + 1) - '0';
}

static inline int make_month(const char *s)
{
	int i;

	for (i = 0; i < 12; i++)
		if (!strncmp(monthName[i], s, 3))
			return i+1;
	return 0;
}

time_t parse_time(const char *str, const int str_len)
{
	int hour;
	int min;
	int sec;
	int mday;
	int mon;
	int year;

	if (str[3] == ',') {
		/* Thu, 09 Jan 1993 01:29:59 GMT */

		if (str_len < 29)
			return -1;

		mday = make_num(str+5);
		mon = make_month(str + 8);
		year = 100 * make_num(str + 12) + make_num(str + 14);
		hour = make_num(str + 17);
		min = make_num(str + 20);
		sec = make_num(str + 23);
	}
	else {
		const char *s;
		s = strchr(str, ',');
		if (!s || (str_len - (s - str) < 24)) {
			/* Wed Jun  9 01:29:59 1993 */

			if (str_len < 24)
				return -1;

			mon = make_month(str+4);
			mday = make_num(str+8);
			hour = make_num(str+11);
			min = make_num(str+14);
			sec = make_num(str+17);
			year = make_num(str+20)*100 + make_num(str+22);
		}
		else {
			/* Thursday, 10-Jun-93 01:29:59 GMT */

			mday = make_num(s + 2);
			mon = make_month(s + 5);
			year = make_num(s + 9) + 1900;
			if (year < 1970)
				year += 100;
			hour = make_num(s + 12);
			min = make_num(s + 15);
			sec = make_num(s + 18);
		}
	}

	if (sec < 0 || sec > 59)
		return -1;
	if (min < 0 || min > 59)
		return -1;
	if (hour < 0 || hour > 23)
		return -1;
	if (mday < 1 || mday > 31)
		return -1;
	if (mon < 1 || mon > 12)
		return -1;
	if (year < 1970 || year > 2020)
		return -1;

	return mktime(year, mon, mday, hour, min, sec);
}
