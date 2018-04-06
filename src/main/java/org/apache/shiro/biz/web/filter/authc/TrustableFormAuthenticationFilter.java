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

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.exception.IncorrectCaptchaException;
import org.apache.shiro.biz.authc.token.CaptchaAuthenticationToken;
import org.apache.shiro.biz.web.filter.CaptchaResolver;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TrustableFormAuthenticationFilter extends FormAuthenticationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(TrustableFormAuthenticationFilter.class);

	/**
     * 是否校验验证码
     */
	private boolean captchaEnabled = false;
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

			if (isCaptchaEnabled() && token instanceof CaptchaAuthenticationToken) {
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
	
	
	public CaptchaResolver getCaptchaResolver() {
		return captchaResolver;
	}

	public void setCaptchaResolver(CaptchaResolver captchaResolver) {
		this.captchaResolver = captchaResolver;
	}

	public boolean isCaptchaEnabled() {
		return captchaEnabled && captchaResolver != null;
	}

	public void setCaptchaEnabled(boolean captchaEnabled) {
		this.captchaEnabled = captchaEnabled;
	}
	
}
