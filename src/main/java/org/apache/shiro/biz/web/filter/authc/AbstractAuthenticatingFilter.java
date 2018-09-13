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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 抽象的认证 (authentication)过滤器
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public abstract class AbstractAuthenticatingFilter extends FormAuthenticationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractAuthenticatingFilter.class);
	
	/**
	 * Login callback listener
	 */
	private List<LoginListener> loginListeners;
	/**
	 * If Session Stateless
	 */
	private boolean sessionStateless = false;
	/**
     * The URL to which users should be redirected if they are denied access to an underlying path or resource,
     * {@code null} by default which will issue a raw {@link HttpServletResponse#SC_UNAUTHORIZED} response
     * (401 Unauthorized).
     */
    private String unauthorizedUrl;
    
	public AbstractAuthenticatingFilter() {
		setLoginUrl(DEFAULT_LOGIN_URL);
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
	
	/**
     * Rewrite the response logic after successful login: JSON information write back
     */
    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject,
                                     ServletRequest request, ServletResponse response) throws Exception {
    	
    	// Call event listener
		if(getLoginListeners() != null && getLoginListeners().size() > 0){
			for (LoginListener loginListener : getLoginListeners()) {
				loginListener.onLoginSuccess(token, subject, request, response);
			}
		}
		
		if (WebUtils.isAjaxRequest(request)) {
			
			// Response success status information
			Map<String, Object> data = new HashMap<String, Object>();
			data.put("status", "success");
			data.put("message", "Authentication Success.");
			// 响应
			WebUtils.writeJSONString(response, data);
			
			return false;
		}
        
		issueSuccessRedirect(request, response);
        //we handled the success , prevent the chain from continuing:
        return false;
    }
	
    /**
     * Response logic after rewriting failed successfully: increase the number of failed records
     */
    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                     ServletRequest request, ServletResponse response) {
    	
    	// Call event listener
		if(getLoginListeners() != null && getLoginListeners().size() > 0){
			for (LoginListener loginListener : getLoginListeners()) {
				loginListener.onLoginFailure(token, e, request, response);
			}
		}
    			
        if (LOG.isDebugEnabled()) {
        	LOG.debug( "Authentication exception", e );
        }
        setFailureAttribute(request, e);
        
        // Login failed, let the request continue to process the response message in the specific business logic
        return true;
    }
    
	@Override
	protected String getHost(ServletRequest request) {
		return WebUtils.getRemoteAddr(request);
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
	
	public List<LoginListener> getLoginListeners() {
		return loginListeners;
	}

	public void setLoginListeners(List<LoginListener> loginListeners) {
		this.loginListeners = loginListeners;
	}

	public boolean isSessionStateless() {
		return sessionStateless;
	}

	public void setSessionStateless(boolean sessionStateless) {
		this.sessionStateless = sessionStateless;
	}

    /**
     * Returns the URL to which users should be redirected if they are denied access to an underlying path or resource,
     * or {@code null} if a raw {@link HttpServletResponse#SC_UNAUTHORIZED} response should be issued (401 Unauthorized).
     * <p/>
     * The default is {@code null}, ensuring default web server behavior.  Override this default by calling the
     * {@link #setUnauthorizedUrl(String) setUnauthorizedUrl} method with a meaningful path within your application
     * if you would like to show the user a 'nice' page in the event of unauthorized access.
     *
     * @return the URL to which users should be redirected if they are denied access to an underlying path or resource,
     *         or {@code null} if a raw {@link HttpServletResponse#SC_UNAUTHORIZED} response should be issued (401 Unauthorized).
     */
    public String getUnauthorizedUrl() {
        return unauthorizedUrl;
    }

    /**
     * Sets the URL to which users should be redirected if they are denied access to an underlying path or resource.
     * <p/>
     * If the value is {@code null} a raw {@link HttpServletResponse#SC_UNAUTHORIZED} response will
     * be issued (401 Unauthorized), retaining default web server behavior.
     * <p/>
     * Unless overridden by calling this method, the default value is {@code null}.  If desired, you can specify a
     * meaningful path within your application if you would like to show the user a 'nice' page in the event of
     * unauthorized access.
     *
     * @param unauthorizedUrl the URL to which users should be redirected if they are denied access to an underlying
     *                        path or resource, or {@code null} to a ensure raw {@link HttpServletResponse#SC_UNAUTHORIZED} response is
     *                        issued (401 Unauthorized).
     */
    public void setUnauthorizedUrl(String unauthorizedUrl) {
        this.unauthorizedUrl = unauthorizedUrl;
    }
    
}
