/*
 * Copyright (c) 2010-2020, vindell (https://github.com/vindell).
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

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractAuthenticatingFilter extends AuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractAuthenticatingFilter.class);
	
	public static final String DEFAULT_ERROR_KEY_ATTRIBUTE_NAME = "shiroLoginFailure";
	
	protected String failureKeyAttribute = DEFAULT_ERROR_KEY_ATTRIBUTE_NAME;
	
	/**
	 * 登录回调监听
	 */
	protected List<LoginListener> loginListeners;
	
	@Override
	protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request,
			ServletResponse response) {
		//调用事件监听器
		if(getLoginListeners() != null && getLoginListeners().size() > 0){
			for (LoginListener loginListener : getLoginListeners()) {
				loginListener.onLoginFailure(token, e, request, response);
			}
		}
		setFailureAttribute(request, e);
		return super.onLoginFailure(token, e, request, response);
	}
	
	@Override
	protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {
		//调用事件监听器
		if(getLoginListeners() != null && getLoginListeners().size() > 0){
			for (LoginListener loginListener : getLoginListeners()) {
				loginListener.onLoginSuccess(token, subject, request, response);
			}
		}
		issueSuccessRedirect(request, response);
		return super.onLoginSuccess(token, subject, request, response);
	}
	
	/**
	 * 登陆成功后重新生成session【基于安全考虑】
	 * 
	 * @param oldSession
	 */
	protected Session newSession(Subject subject, Session oldSession) {
		// retain Session attributes to put in the new session after login:
		Map<Object, Object> attributes = new LinkedHashMap<Object, Object>();

		Collection<Object> keys = oldSession.getAttributeKeys();

		for (Object key : keys) {
			Object value = oldSession.getAttribute(key);
			if (value != null) {
				attributes.put(key, value);
			}
		}
		oldSession.stop();
		// restore the attributes:
		Session newSession = subject.getSession();

		for (Object key : attributes.keySet()) {
			newSession.setAttribute(key, attributes.get(key));
		}
		return newSession;
	}

	@Override
	public void setLoginUrl(String loginUrl) {
		String previous = getLoginUrl();
		if (previous != null) {
			this.appliedPaths.remove(previous);
		}
		super.setLoginUrl(loginUrl);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Adding login url to applied paths.");
		}
		this.appliedPaths.put(getLoginUrl(), null);
	}

	public String getFailureKeyAttribute() {
		return failureKeyAttribute;
	}

	public void setFailureKeyAttribute(String failureKeyAttribute) {
		this.failureKeyAttribute = failureKeyAttribute;
	}

	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		if (isLoginRequest(request, response)) {
			if (isLoginSubmission(request, response)) {
				if (LOG.isTraceEnabled()) {
					LOG.trace("Login submission detected.  Attempting to execute login.");
				}
				return executeLogin(request, response);
			} else {
				if (LOG.isTraceEnabled()) {
					LOG.trace("Login page view.");
				}
				// allow them to see the login page ;)
				return true;
			}
		} else {
			if (LOG.isTraceEnabled()) {
				LOG.trace("Attempting to access a path which requires authentication.  Forwarding to the "
						+ "Authentication url [" + getLoginUrl() + "]");
			}
			saveRequestAndRedirectToLogin(request, response);
			return false;
		}
	}

	/**
	 * This default implementation merely returns <code>true</code> if the
	 * request is an HTTP <code>POST</code>, <code>false</code> otherwise. Can
	 * be overridden by subclasses for custom login submission detection
	 * behavior.
	 *
	 * @param request the incoming ServletRequest
	 * @param response the outgoing ServletResponse.
	 * @return <code>true</code> if the request is an HTTP <code>POST</code>,
	 *         <code>false</code> otherwise.
	 */
	protected boolean isLoginSubmission(ServletRequest request, ServletResponse response) {
		return (request instanceof HttpServletRequest)
				&& WebUtils.toHttp(request).getMethod().equalsIgnoreCase(POST_METHOD);
	}

	protected void setFailureAttribute(ServletRequest request, AuthenticationException ae) {
		String className = ae.getClass().getName();
		request.setAttribute(getFailureKeyAttribute(), className);
	}
	
	
	public List<LoginListener> getLoginListeners() {
		return loginListeners;
	}

	public void setLoginListeners(List<LoginListener> loginListeners) {
		this.loginListeners = loginListeners;
	}

}
