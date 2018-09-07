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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * 抽象的授权 (authorization)过滤器
 * 
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public abstract class AbstracAuthorizationFilter extends AuthorizationFilter {

	/**
	 * If Session Stateless
	 */
	private boolean sessionStateless = false;
	private String accessControlAllowOrigin = "*";
	private String accessControlAllowMethods = "PUT,POST,GET,DELETE,OPTIONS";
	private String accessControlAllowHeaders = "*";
	
	/** 对跨域提供支持 */ 
	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
		HttpServletRequest httpServletRequest = WebUtils.toHttp(request);
		HttpServletResponse httpServletResponse = WebUtils.toHttp(response);
		httpServletResponse.setHeader("Access-Control-Allow-Origin", StringUtils.getSafeStr(getAccessControlAllowOrigin(), httpServletRequest.getHeader("Origin")));
		httpServletResponse.setHeader("Access-Control-Allow-Methods", StringUtils.getSafeStr(getAccessControlAllowMethods(), httpServletRequest.getHeader("Access-Control-Request-Headers")));
		httpServletResponse.setHeader("Access-Control-Allow-Headers", StringUtils.getSafeStr(getAccessControlAllowHeaders(), httpServletRequest.getHeader("Access-Control-Request-Headers")) );
		// 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
		if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
			httpServletResponse.setStatus(HttpServletResponse.SC_OK);
			return false;
		}
		return super.preHandle(request, response);
	}
	
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
	
	@Override
	protected Subject getSubject(ServletRequest request, ServletResponse response) {
		if(isSessionStateless()) {
			// 重写Subject对象获取逻辑,解决认证信息缓存问题，达到每次认证都是一次新的认证
			Subject subject = (new Subject.Builder()).buildSubject();
	        ThreadContext.bind(subject);
	        return subject;
		}
		return super.getSubject(request, response);
	}
	
	protected boolean onAccessSuccess(Object mappedValue, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {
		return true;
	}

	protected boolean onAccessFailure(Object mappedValue, Exception e, ServletRequest request,
			ServletResponse response) {
		return false;
	}
	
	protected String getHost(ServletRequest request) {
		return WebUtils.getRemoteAddr(request);
	}

	public boolean isSessionStateless() {
		return sessionStateless;
	}

	public void setSessionStateless(boolean sessionStateless) {
		this.sessionStateless = sessionStateless;
	}

	public String getAccessControlAllowOrigin() {
		return accessControlAllowOrigin;
	}

	public void setAccessControlAllowOrigin(String accessControlAllowOrigin) {
		this.accessControlAllowOrigin = accessControlAllowOrigin;
	}

	public String getAccessControlAllowMethods() {
		return accessControlAllowMethods;
	}

	public void setAccessControlAllowMethods(String accessControlAllowMethods) {
		this.accessControlAllowMethods = accessControlAllowMethods;
	}

	public String getAccessControlAllowHeaders() {
		return accessControlAllowHeaders;
	}

	public void setAccessControlAllowHeaders(String accessControlAllowHeaders) {
		this.accessControlAllowHeaders = accessControlAllowHeaders;
	}

}
