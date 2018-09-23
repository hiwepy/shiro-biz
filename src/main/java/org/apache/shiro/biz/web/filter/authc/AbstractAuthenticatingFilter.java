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

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.exception.SessionRestrictedException;
import org.apache.shiro.biz.authc.exception.TerminalRestrictedException;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.eis.SessionDAO;
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
	private static final String DEFAULT_SESSION_RESTRICTED_ATTR_NAME = "session-restricted";
	/**
	 * Login callback listener
	 */
	private List<LoginListener> loginListeners;
	/** SessionDAO */
	private SessionDAO sessionDao; 
	/** If Session Stateless */
	private boolean sessionStateless = false;
	/** If Session Maximum Restricted */
	private boolean sessionRestrictable = false;
	/** The tag that the sessions has been restricted. */
	private String sessionRestrictedAttributeName = DEFAULT_SESSION_RESTRICTED_ATTR_NAME;
	/** Maximum number of sessions in the same Servlet Container . */
	private int sessionMaximumRestrict = 1000;
	/** Maximum number of sessions for users logging in different terminals . */
	private int sessionTerminalRestrict = 1;
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
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		return isSessionStateless() ? false : super.isAccessAllowed(request, response, mappedValue);
	}
	
	@Override
	protected Subject getSubject(ServletRequest request, ServletResponse response) {
		if(isSessionStateless()) {
			/*
			 * Rewrite the Subject object to get the logic, 
			 * solve the authentication information cache problem, 
			 * and achieve a new authentication every time.
			 */
			Subject subject = (new Subject.Builder()).buildSubject();
	        ThreadContext.bind(subject);
	        return subject;
		}
		return super.getSubject(request, response);
	}
	
	@Override
	protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
		
		AuthenticationToken token = createToken(request, response);
        if (token == null) {
            String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken " +
                    "must be created in order to execute a login attempt.";
            throw new IllegalStateException(msg);
        }
        
        try {
        	
            Subject subject = getSubject(request, response);
            
            // Check If Session Maximum Restricted
            if(isSessionRestrictable()) {
            	if(sessionDao == null){
        			throw new IllegalStateException("sessionDao must be set for this filter");
        		}
            	Collection<Session> sessions = getSessionDao().getActiveSessions();
            	// 根据session数量判断在线人数是否已经超出限制
            	// Determine whether the online number has exceeded the limit based on the number of sessions.
        		if(sessions.size() >= getSessionMaximumRestrict() ){
        			throw new SessionRestrictedException("Online user quota is full, please login again later.");
        		}
    			// 根据session中的标记判断用户在多个终端的会话是否已经超出限制
       			// According to the mark in the session, it is judged whether the user's session on multiple terminals has exceeded the limit.
        		int userRepeatNumber = 0;
        		for(Session session : sessions){         
        			Object attr = session.getAttribute(getSessionRestrictedAttributeName());
        			if( attr != null && attr.equals(token.getPrincipal()) ){
    					userRepeatNumber ++;
        			}
        			if(userRepeatNumber >= getSessionTerminalRestrict()){
        				throw new TerminalRestrictedException("This user terminal login quota is full, please log in later.");
        			}
    			}
        		subject.getSession().setAttribute(getSessionRestrictedAttributeName(), token.getPrincipal());
            }
            subject.login(token);
            return onLoginSuccess(token, subject, request, response);
        } catch (AuthenticationException e) {
            return onLoginFailure(token, e, request, response);
        }
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

    public SessionDAO getSessionDao() {
		return sessionDao;
	}

	public void setSessionDao(SessionDAO sessionDao) {
		this.sessionDao = sessionDao;
	}
	
	public boolean isSessionStateless() {
		return sessionStateless;
	}

	public void setSessionStateless(boolean sessionStateless) {
		this.sessionStateless = sessionStateless;
	}
	
	public boolean isSessionRestrictable() {
		return sessionRestrictable;
	}

	public void setSessionRestrictable(boolean sessionRestrictable) {
		this.sessionRestrictable = sessionRestrictable;
	}

	public String getSessionRestrictedAttributeName() {
		return sessionRestrictedAttributeName;
	}

	public void setSessionRestrictedAttributeName(String sessionRestrictedAttributeName) {
		this.sessionRestrictedAttributeName = sessionRestrictedAttributeName;
	}

	public int getSessionMaximumRestrict() {
		return sessionMaximumRestrict;
	}

	public void setSessionMaximumRestrict(int sessionMaximumRestrict) {
		this.sessionMaximumRestrict = sessionMaximumRestrict;
	}

	public int getSessionTerminalRestrict() {
		return sessionTerminalRestrict;
	}

	public void setSessionTerminalRestrict(int sessionTerminalRestrict) {
		this.sessionTerminalRestrict = sessionTerminalRestrict;
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
