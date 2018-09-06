/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
package org.apache.shiro.biz.web.filter.authc;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.shiro.biz.utils.WebUtils;

public class AuthenticatingFailureSessionCounter implements AuthenticatingFailureCounter {

	@Override
	public int get(ServletRequest request, ServletResponse response, String retryTimesKeyAttribute) {
		HttpSession session = WebUtils.toHttp(request).getSession();
		Object count = session.getAttribute(retryTimesKeyAttribute);
		if (null != count) {
			return Integer.parseInt(String.valueOf(count));
		}
		return 0;
	}

	@Override
	public void increment(ServletRequest request, ServletResponse response, String retryTimesKeyAttribute) {
		HttpSession session = WebUtils.toHttp(request).getSession();
		Object count = session.getAttribute(retryTimesKeyAttribute);
		if (null == count) {
			session.setAttribute(retryTimesKeyAttribute, 1);
		} else {
			session.setAttribute(retryTimesKeyAttribute, Long.parseLong(String.valueOf(count)) + 1);
		}
	}

}
