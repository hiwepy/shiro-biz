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
package org.apache.shiro.biz.web.filter.authz;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

/**
 * 抽象的授权 (authorization)过滤器 
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public abstract class AbstracAuthorizationFilter extends AuthorizationFilter {

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
		Subject subject = getSubject(request, response);
		// 未认证
		if (null == subject.getPrincipal()) {
			// Ajax 请求：响应json数据对象
			if (WebUtils.isAjaxRequest(request)) {
				WebUtils.writeJSONString(response, HttpServletResponse.SC_UNAUTHORIZED, "Unauthentication.");
				return false;
			}
			// 普通请求：重定向到登录页
			saveRequestAndRedirectToLogin(request, response);
			return false;
		} else {
			if (WebUtils.isAjaxRequest(request)) {
				WebUtils.writeJSONString(response, HttpServletResponse.SC_FORBIDDEN, "Forbidden.");
				return false;
			} else {
				// If subject is known but not authorized, redirect to the unauthorized URL if
				// there is one
				// If no unauthorized URL is specified, just return an unauthorized HTTP status
				// code
				String unauthorizedUrl = getUnauthorizedUrl();
				// SHIRO-142 - ensure that redirect _or_ error code occurs - both cannot happen
				// due to response commit:
				if (StringUtils.hasText(unauthorizedUrl)) {
					WebUtils.issueRedirect(request, response, unauthorizedUrl);
				} else {
					WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
				}
			}
		}
		return false;
	}

}
