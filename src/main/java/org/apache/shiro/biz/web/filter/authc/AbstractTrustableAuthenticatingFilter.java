/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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
import org.apache.shiro.biz.authc.AuthenticationFailureHandler;
import org.apache.shiro.biz.authc.exception.IncorrectCaptchaException;
import org.apache.shiro.biz.authc.exception.NoneCaptchaException;
import org.apache.shiro.biz.authc.token.CaptchaAuthenticationToken;
import org.apache.shiro.biz.authc.token.DefaultAuthenticationToken;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.captcha.CaptchaResolver;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 抽象的可信的认证 (authentication)过滤器
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public abstract class AbstractTrustableAuthenticatingFilter extends AbstractAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractTrustableAuthenticatingFilter.class);
	public static final String DEFAULT_CAPTCHA_PARAM = "captcha";
	public static final String DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME = "shiroLoginFailureRetries";
	public static final String DEFAULT_ACCESS_CONTROL_ALLOW_METHODS = "PUT,POST,GET,DELETE,OPTIONS";
	
	private boolean captchaEnabled = false;
	private String captchaParam = DEFAULT_CAPTCHA_PARAM;
    private String retryTimesKeyAttribute = DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME;
    /** Maximum number of retry to login . */
	private int retryTimesWhenAccessDenied = 3;
	private CaptchaResolver captchaResolver;
	private AuthenticatingFailureCounter failureCounter;
	
	public AbstractTrustableAuthenticatingFilter() {
		super();
	}
	
	@Override
	protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
		AuthenticationToken token = createToken(request, response);
		if (token == null) {
			String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken "
					+ "must be created in order to execute a login attempt.";
			throw new AuthenticationException(msg);
		}
		try {
			
			if (token instanceof CaptchaAuthenticationToken  &&  isOverRetryTimes(request, response)) {
				boolean validation = captchaResolver.validCaptcha(request, (CaptchaAuthenticationToken) token);
				if (!validation) {
					throw new IncorrectCaptchaException("Captcha validation failed!");
				}
			}
			Subject subject = getSubject(request, response);
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
		// Determine if a verification code check is required
		if (isCaptchaEnabled()) {
			return new DefaultAuthenticationToken(username, password, getCaptcha(request), rememberMe, host);
		}
		
		return new DefaultAuthenticationToken(username, password, rememberMe, host);
	}
	
    /**
     * Response logic after rewriting failed successfully: increase the number of failed records
     */
    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                     ServletRequest request, ServletResponse response) {
    	
        if (LOG.isDebugEnabled()) {
        	LOG.debug( "Authentication exception", e );
        }
        
		if( WebUtils.isAjaxResponse(request)) {
			
			if (CollectionUtils.isEmpty(getFailureHandlers())) {
				this.writeFailureString(token , e, request, response);
			} else {
				boolean isMatched = false;
				for (AuthenticationFailureHandler failureHandler : getFailureHandlers()) {

					if (failureHandler != null && failureHandler.supports(e)) {
						failureHandler.onAuthenticationFailure(token, request, response, e);
						isMatched = true;
						break;
					}
				}
				if (!isMatched) {
					this.writeFailureString(token , e, request, response);
				}
			}
			
			return false;
		}
		
        setFailureAttribute(request, e);
        setFailureCountAttribute(request, response, e);
        // The retry limit has been exceeded and a reminder is required
        if(isCaptchaEnabled() && isOverRetryRemind(request, response)) {
        	setFailureAttribute(request, new NoneCaptchaException("The number of login errors exceeds the maximum retry limit and a verification code is required."));
        }
        // Login failed, let the request continue to process the response message in the specific business logic
        return true;
    }
    
	protected void setFailureCountAttribute(ServletRequest request, ServletResponse response,
				AuthenticationException ae) {
		if(null != getFailureCounter()) {
			getFailureCounter().increment(request, response, getRetryTimesKeyAttribute());
		}
	}
	
    protected String getCaptcha(ServletRequest request) {
		return WebUtils.getCleanParam(request, getCaptchaParam());
	}
	
	@Override
	protected String getHost(ServletRequest request) {
		return WebUtils.getRemoteAddr(request);
	}
	
	protected boolean isOverRetryRemind(ServletRequest request, ServletResponse response) {
		if (null != getFailureCounter() && getFailureCounter().get(request, response, getRetryTimesKeyAttribute()) == getRetryTimesWhenAccessDenied()) {
			return true;
		}
		return false;
	}
	
	protected boolean isOverRetryTimes(ServletRequest request, ServletResponse response) {
		if (null != getFailureCounter() && getFailureCounter().get(request, response, getRetryTimesKeyAttribute()) >= getRetryTimesWhenAccessDenied()) {
			return true;
		}
		return false;
	}
	
	protected boolean onAccessSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response)  {
		// Successful authentication, continue the original access request
        return true;
	}

	protected boolean onAccessFailure(AuthenticationToken token, Exception e, ServletRequest request,
			ServletResponse response) {
		
		return false;
	}
	
	public boolean isCaptchaEnabled() {
		return captchaEnabled && null != captchaResolver;
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

	public CaptchaResolver getCaptchaResolver() {
		return captchaResolver;
	}

	public void setCaptchaResolver(CaptchaResolver captchaResolver) {
		this.captchaResolver = captchaResolver;
	}

	public AuthenticatingFailureCounter getFailureCounter() {
		return failureCounter;
	}

	public void setFailureCounter(AuthenticatingFailureCounter failureCounter) {
		this.failureCounter = failureCounter;
	}
	
}
