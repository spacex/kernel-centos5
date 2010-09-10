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


#include "times.h"

char *dayName[7] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static char *monthName[12] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
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
	int Y=0,M=0,D=0;
	int H=0,Min=0,S=0,WD=0;
	int I,I2;
	time_t rest, delta;

	if (zulu > xtime.tv_sec)
		zulu = xtime.tv_sec;

	I=0;
	while (I<TUX_NUMYEARS) {
		if (TimeDays[I][0]>zulu)
		   break;
		I++;
	}

	Y=--I;
	if (I<0) {
		Y=0;
		goto BuildYear;
	}
	I2=0;
	while (I2<=12) {
		if (TimeDays[I][I2]>zulu)
		   break;
		I2++;
	}

	M=I2-1;

	rest=zulu - TimeDays[Y][M];
	WD=WeekDays[Y][M];
	D=rest/86400;
	rest=rest%86400;
	WD+=D;
	WD=WD%7;
	H=rest/3600;
	rest=rest%3600;
	Min=rest/60;
	rest=rest%60;
	S=rest;

BuildYear:
	Y+=TUX_YEAROFFSET;


	/* Format:  Day, 01 Mon 1999 01:01:01 GMT */

	delta = xtime.tv_sec - zulu;
	if (delta > 6*30*24*60)
		//               "May 23   2000"
		return sprintf( buf, "%s %02i  %04i", monthName[M], D+1, Y);
	else
		//                "May 23 10:14"
		return sprintf( buf, "%s %02i %02i:%02i",
			monthName[M], D+1, H, Min);
}

static int MonthHash[32] =
	{0,0,7,0,0,0,0,0,0,0,0,3,0,0,0,2,6,0,5,0,9,8,4,0,0,11,1,10,0,0,0,0};

#define is_digit(c)	((c) >= '0' && (c) <= '9')

static inline int skip_atoi(char **s)
{
	int i=0;

	while (is_digit(**s))
		i = i*10 + *((*s)++) - '0';
	return i;
}

time_t mimetime_to_unixtime(char *Q)
{
	int Y,M,D,H,Min,S;
	unsigned int Hash;
	time_t Temp;
	char *s,**s2;

	s=Q;
	s2=&s;

	if (strlen(s)<30) return 0;
	if (s[3]!=',') return 0;
	if (s[19]!=':') return 0;

	s+=5; /* Skip day of week */
	D = skip_atoi(s2);  /*  Day of month */
	s++;
	Hash = (char)s[0]+(char)s[2];
	Hash = (Hash<<1) + (char)s[1];
	Hash = (Hash&63)>>1;
	M = MonthHash[Hash];
	s+=4;
	Y = skip_atoi(s2); /* Year */
	s++;
	H = skip_atoi(s2); /* Hour */
	s++;
	Min = skip_atoi(s2); /* Minutes */
	s++;
	S = skip_atoi(s2); /* Seconds */
	s++;
	if ((s[0]!='G')||(s[1]!='M')||(s[2]!='T'))
	{
		return 0; /* No GMT */
	}

	if (Y<TUX_YEAROFFSET) Y = TUX_YEAROFFSET;
	if (Y>TUX_YEAROFFSET+9) Y = TUX_YEAROFFSET+9;

	Temp = TimeDays[Y-TUX_YEAROFFSET][M];
	Temp += D*86400+H*3600+Min*60+S;

	return Temp;
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
