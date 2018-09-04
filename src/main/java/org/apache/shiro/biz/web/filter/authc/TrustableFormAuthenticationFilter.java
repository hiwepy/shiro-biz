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
package org.apache.shiro.biz.web.filter.authc;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.exception.IncorrectCaptchaException;
import org.apache.shiro.biz.authc.token.CaptchaAuthenticationToken;
import org.apache.shiro.biz.authc.token.DefaultAuthenticationToken;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.captcha.CaptchaResolver;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TrustableFormAuthenticationFilter extends FormAuthenticationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(TrustableFormAuthenticationFilter.class);
    public static final String DEFAULT_CAPTCHA_PARAM = "captcha";
	public static final String DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME = "shiroLoginFailureRetries";

	private boolean captchaEnabled = false;
	private String captchaParam = DEFAULT_CAPTCHA_PARAM;
	private String retryTimesKeyAttribute = DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME;
    /** Maximum number of retry to login . */
	private int retryTimesWhenAccessDenied = 3;
	/** 是否重定向到前一个访问地址 */
	private boolean redirectToSavedRequest;
	private CaptchaResolver captchaResolver;
	
	public TrustableFormAuthenticationFilter() {
		setLoginUrl(DEFAULT_LOGIN_URL);
	}
	
	@Override
	protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
		Subject subject = getSubject(request, response);
		AuthenticationToken token = createToken(request, response);
		if (subject.isAuthenticated()) {
			LOG.info("User has already been Authenticated!");
			return onLoginSuccess(token, subject, request, response);
		}
		try {
			if (token == null) {
				String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken "
						+ "must be created in order to execute a login attempt.";
				throw new AuthenticationException(msg);
			}

			if (token instanceof CaptchaAuthenticationToken && isOverRetryTimes(request, response)) {
				boolean validation = captchaResolver.validCaptcha(request, (CaptchaAuthenticationToken) token);
				if (!validation) {
					throw new IncorrectCaptchaException("Captcha validation failed!");
				}
			}
			subject.login(token);
			return onLoginSuccess(token, subject, request, response);
		} catch (AuthenticationException e) {
			return onLoginFailure(token, e, request, response);
		}
	}
	
	@Override
	protected AuthenticationToken createToken(String username, String password, ServletRequest request,
			ServletResponse response) {

		boolean rememberMe = isRememberMe(request);
		String host = getHost(request);
		// 判断是否需要进行验证码检查
		if (isCaptchaEnabled()) {

			DefaultAuthenticationToken token = new DefaultAuthenticationToken(username, password);

			token.setHost(host);
			token.setRememberMe(rememberMe);
			token.setCaptcha(getCaptcha(request));

			return token;
		}
		return super.createToken(username, password, rememberMe, host);

	}

	@Override
	protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {
		
		if(isRedirectToSavedRequest()) {
			issueSuccessRedirect(request, response);
		} else {
			 WebUtils.issueRedirect(request, response, getSuccessUrl());
		}
		//we handled the success redirect directly, prevent the chain from continuing:
        return false;
	}
	
	/**
     * 重写成功失败后的响应逻辑：增加失败次数记录
     */
    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                     ServletRequest request, ServletResponse response) {
        if (LOG.isDebugEnabled()) {
        	LOG.debug( "Authentication exception", e );
        }
        setFailureAttribute(request, e);
        setFailureCountAttribute(request, response, e);
        // 已经超出了重试限制，需要进行提醒
        if(isOverRetryTimes(request, response)) {
        	WebUtils.getHttpRequest(request).setAttribute("captcha", "1");
        }
        
        //login failed, let request continue back to the login page:
        return true;
    }
	
	protected void setFailureAttribute(ServletRequest request, AuthenticationException ae) {
        String className = ae.getClass().getName();
        request.setAttribute(getFailureKeyAttribute(), className);
    }

	protected void setFailureCountAttribute(ServletRequest request, ServletResponse response,
			AuthenticationException ae) {

		Session session = getSubject(request, response).getSession(true);
		Object count = session.getAttribute(getRetryTimesKeyAttribute());
		if (null == count) {
			session.setAttribute(getRetryTimesKeyAttribute(), 1);
		} else {
			session.setAttribute(getRetryTimesKeyAttribute(), Long.parseLong(String.valueOf(count)) + 1);
		}
		
	}

	@Override
	protected String getHost(ServletRequest request) {
		return WebUtils.getRemoteAddr(request);
	}
	
	protected String getCaptcha(ServletRequest request) {
		return WebUtils.getCleanParam(request, getCaptchaParam());
	}
	
	protected boolean isOverRetryTimes(ServletRequest request, ServletResponse response) {
		Session session = getSubject(request, response).getSession(true);
		Object count = session.getAttribute(getRetryTimesKeyAttribute());
		if (null != count && Long.parseLong(String.valueOf(count)) > getRetryTimesWhenAccessDenied()) {
			return false;
		}
		return true;
	}
	
	public boolean isCaptchaEnabled() {
		return captchaEnabled && captchaResolver != null;
	}

	public void setCaptchaEnabled(boolean captchaEnabled) {
		this.captchaEnabled = captchaEnabled;
	}

	public String getCaptchaParam() {
		return captchaParam;
	}

	public void setCaptchaParam(String captchaParam) {
		this.captchaParam = captchaParam;
	}

	public String getRetryTimesKeyAttribute() {
		return retryTimesKeyAttribute;
	}

	public void setRetryTimesKeyAttribute(String retryTimesKeyAttribute) {
		this.retryTimesKeyAttribute = retryTimesKeyAttribute;
	}

	public int getRetryTimesWhenAccessDenied() {
		return retryTimesWhenAccessDenied;
	}

	public void setRetryTimesWhenAccessDenied(int retryTimesWhenAccessDenied) {
		this.retryTimesWhenAccessDenied = retryTimesWhenAccessDenied;
	}

	public boolean isRedirectToSavedRequest() {
		return redirectToSavedRequest;
	}

	public void setRedirectToSavedRequest(boolean redirectToSavedRequest) {
		this.redirectToSavedRequest = redirectToSavedRequest;
	}
	
	public CaptchaResolver getCaptchaResolver() {
		return captchaResolver;
	}

	public void setCaptchaResolver(CaptchaResolver captchaResolver) {
		this.captchaResolver = captchaResolver;
	}
	
}
