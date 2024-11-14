package com.raonsecure.odi.wallet.util;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class TimeUtil {

	private static final DateFormat DATE_FROMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

	public String setExpiresDayFromCurrent(int years) {

		Calendar expireCal = new GregorianCalendar();
		expireCal.setTime(new Date());
		expireCal.add(Calendar.YEAR, years);
		expireCal.set(Calendar.HOUR_OF_DAY, 23);
		expireCal.set(Calendar.MINUTE, 59);
		expireCal.set(Calendar.SECOND, 59);
		expireCal.set(Calendar.MILLISECOND, 999);

		return dateToString(expireCal.getTime());

	}

	public String dateToString(Date date) {
		return DATE_FROMAT.format(date);
	}

	public Date stringToDate(String date) {
		try {
			return DATE_FROMAT.parse(date);
		} catch (ParseException e) {
//			e.printStackTrace();
		}
		return null;
	}

}
