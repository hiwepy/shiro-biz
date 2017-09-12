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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.exception.IncorrectCaptchaException;
import org.apache.shiro.biz.authc.token.CaptchaAuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractCaptchaAuthenticatingFilter extends AbstractAuthenticatingFilter {
	
	private static final Logger LOG = LoggerFactory.getLogger(AbstractCaptchaAuthenticatingFilter.class);

	public static final String DEFAULT_SESSION_CAPTCHA_KEY = "KAPTCHA_SESSION_KEY";

	protected boolean validateCaptcha = false;

	protected String sessoionCaptchaKey = DEFAULT_SESSION_CAPTCHA_KEY;

	public AbstractCaptchaAuthenticatingFilter() {
		setLoginUrl(DEFAULT_LOGIN_URL);
	}

	protected void validateCaptcha(Session session, CaptchaAuthenticationToken token) {
		boolean validation = true;
		if (isValidateCaptcha()) {
			validation = validateCaptcha((String) session.getAttribute(getSessoionCaptchaKey()), token.getCaptcha());
		}
		if (!validation) {
			throw new IncorrectCaptchaException("Captcha validation failed!");
		}
	}

	protected boolean validateCaptcha(String request, String token) {
		if (StringUtils.isEmpty(request)) {
			return false;
		}
		return StringUtils.equalsIgnoreCase(request, token);
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

			if (token instanceof CaptchaAuthenticationToken) {
				validateCaptcha(subject.getSession(), (CaptchaAuthenticationToken) token);
			}

			subject.login(token);
			return onLoginSuccess(token, subject, request, response);
		} catch (AuthenticationException e) {
			return onLoginFailure(token, e, request, response);
		}
	}

	public boolean isValidateCaptcha() {
		return validateCaptcha;
	}

	public void setValidateCaptcha(boolean validateCaptcha) {
		this.validateCaptcha = validateCaptcha;
	}

	public String getSessoionCaptchaKey() {
		return sessoionCaptchaKey;
	}

	public void setSessoionCaptchaKey(String sessoionCaptchaKey) {
		this.sessoionCaptchaKey = sessoionCaptchaKey;
	}

}
