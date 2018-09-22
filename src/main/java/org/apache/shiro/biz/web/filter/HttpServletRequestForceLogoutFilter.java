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
package org.apache.shiro.biz.web.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.Constants;
import org.apache.shiro.session.Session;
import org.apache.shiro.web.filter.AccessControlFilter;

/**
 * http://jinnianshilongnian.iteye.com/blog/2047643
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class HttpServletRequestForceLogoutFilter extends AccessControlFilter {

	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		Session session = getSubject(request, response).getSession(false);
		if (session == null) {
			return true;
		}
		return session.getAttribute(Constants.SESSION_FORCE_LOGOUT_KEY) == null;
	}

	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		try {
			getSubject(request, response).logout();// 强制退出
		} catch (Exception e) {
			/* ignore exception */}
		String loginUrl = getLoginUrl() + (getLoginUrl().contains("?") ? "&" : "?") + "forceLogout=1";
		WebUtils.issueRedirect(request, response, loginUrl);
		return false;
	}

}