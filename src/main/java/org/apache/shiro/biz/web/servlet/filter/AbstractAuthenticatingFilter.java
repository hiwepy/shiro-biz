package org.apache.shiro.biz.web.servlet.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.util.WebUtils;

public abstract class AbstractAuthenticatingFilter extends AccessControlFilter {

    // Reference to the security manager used by this filter
    private WebSecurityManager securityManager;

	/**
     * Simple default login URL equal to <code>/login.jsp</code>, which can be overridden by calling the
     * {@link #setLoginUrl(String) setLoginUrl} method.
     */
    public static final String DEFAULT_LOGIN_URL = "/login.jsp";

	public static final String DEFAULT_SUCCESS_URL = "/";
	
    /**
     * The login url to used to authenticate a user, used when redirecting users if authentication is required.
     */
    private String loginUrl = DEFAULT_LOGIN_URL;
    
    private String successUrl = DEFAULT_SUCCESS_URL;
    
    @Override
    protected void onFilterConfigSet() throws Exception {
    	super.onFilterConfigSet();
    	this.setLoginUrl(getFilterConfig().getInitParameter("loginUrl"));
		this.setSuccessUrl(getFilterConfig().getInitParameter("successUrl"));
    }
    
    @Override
    public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
    		throws ServletException, IOException {
    	
    	// 在不经过Shiro过滤器的情况下进行单点登录时，需要绑定Subject到ThreadContext中
    	Subject subject = ThreadContext.getSubject();
        if (subject == null) {
            subject = new WebSubject.Builder(getSecurityManager(), request, response).buildWebSubject();
            ThreadContext.bind(subject);
        }
    	
    	super.doFilterInternal(request, response, chain);
    }
    
	/**
     * Redirects to user to the previously attempted URL after a successful login.  This implementation simply calls
     * <code>{@link org.apache.shiro.web.util.WebUtils WebUtils}.{@link WebUtils#redirectToSavedRequest(javax.servlet.ServletRequest, javax.servlet.ServletResponse, String) redirectToSavedRequest}</code>
     * using the {@link #getSuccessUrl() successUrl} as the {@code fallbackUrl} argument to that call.
     *
     * @param request  the incoming request
     * @param response the outgoing response
     * @throws IOException if there is a problem redirecting.
     */
    protected void issueSuccessRedirect(ServletRequest request, ServletResponse response) throws IOException {
        WebUtils.redirectToSavedRequest(request, response, getSuccessUrl());
    }
    
    /**
     * Convenience method for subclasses to use when a login redirect is required.
     * This implementation simply calls {@link #saveRequest(javax.servlet.ServletRequest) saveRequest(request)}
     * and then {@link #redirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse) redirectToLogin(request,response)}.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @throws IOException if an error occurs.
     */
    protected void saveRequestAndRedirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        saveRequest(request);
        redirectToLogin(request, response);
    }

    /**
     * Convenience method merely delegates to
     * {@link WebUtils#saveRequest(javax.servlet.ServletRequest) WebUtils.saveRequest(request)} to save the request
     * state for reuse later.  This is mostly used to retain user request state when a redirect is issued to
     * return the user to their originally requested url/resource.
     * If you need to save and then immediately redirect the user to login, consider using
     * {@link #saveRequestAndRedirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
     * saveRequestAndRedirectToLogin(request,response)} directly.
     *
     * @param request the incoming ServletRequest to save for re-use later (for example, after a redirect).
     */
    protected void saveRequest(ServletRequest request) {
        WebUtils.saveRequest(request);
    }

    /**
     * Convenience method for subclasses that merely acquires the {@link #getLoginUrl() getLoginUrl} and redirects
     * the request to that url.
     * <b>N.B.</b>  If you want to issue a redirect with the intention of allowing the user to then return to their
     * originally requested URL, don't use this method directly.  Instead you should call
     * {@link #saveRequestAndRedirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
     * saveRequestAndRedirectToLogin(request,response)}, which will save the current request state so that it can
     * be reconstructed and re-used after a successful login.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @throws IOException if an error occurs.
     */
    protected void redirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        String loginUrl = getLoginUrl();
        WebUtils.issueRedirect(request, response, loginUrl);
    }
    
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
    		throws Exception {
    	// 已登录会话不进行拦截处理
    	return SecurityUtils.getSubject().isAuthenticated();
    }
    
    public WebSecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(WebSecurityManager sm) {
        this.securityManager = sm;
    }
    
	public String getLoginUrl() {
		return loginUrl;
	}

	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}

	public String getSuccessUrl() {
		return successUrl;
	}

	public void setSuccessUrl(String successUrl) {
		this.successUrl = successUrl;
	}
    
}
