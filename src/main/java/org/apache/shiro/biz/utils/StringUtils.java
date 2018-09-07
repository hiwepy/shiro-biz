/*
 * Copyright (c) 2018 (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.biz.utils;

public abstract class StringUtils extends org.apache.shiro.util.StringUtils {
	
	/**
	 * Any number of these characters are considered delimiters between
	 * multiple context config paths in a single String value.
	 */
	public static String CONFIG_LOCATION_DELIMITERS = ",; \t\n";
	
	//---------------------------------------------------------------------
	// General convenience methods for working with Strings
	//---------------------------------------------------------------------

	/**
	 * Check whether the given String is empty.
	 * <p>This method accepts any Object as an argument, comparing it to
	 * {@code null} and the empty String. As a consequence, this method
	 * will never return {@code true} for a non-null non-String object.
	 * <p>The Object signature is useful for general attribute handling code
	 * that commonly deals with Strings but generally has to iterate over
	 * Objects since attributes may e.g. be primitive value objects as well.
	 * @param str the candidate String
	 * @return 是否为空
	 */
	public static boolean isEmpty(Object str) {
		return (str == null || "".equals(str));
	}
 
	/**
	 * 
	 * 获得以 ",; \t\n"分割的字符数组
	 * @param str 待分割字符串
	 * @return 分割后的字符串数组
	 */
	public static String[] tokenizeToStringArray(String str) {
		return tokenizeToStringArray(str, CONFIG_LOCATION_DELIMITERS, true, true);
	}

    public static String join(final Iterable<?> iterable, final String separator) {
        return org.apache.commons.lang3.StringUtils.join(iterable, separator);
    }

}