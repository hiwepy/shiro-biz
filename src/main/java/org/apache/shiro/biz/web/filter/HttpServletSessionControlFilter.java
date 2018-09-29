package org.apache.shiro.biz.web.filter;

import java.io.Serializable;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;

/**
 * <p>Session Control Filter, 用户session控制 只允许用户在一个地方登录</p>
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public abstract class HttpServletSessionControlFilter extends AccessControlFilter {

	 /**
     * The default session control cache name, equal to {@code shiro-controlSessionCache}.
     */
    public static final String CREDENTIALS_RETRY_CACHE_NAME = "shiro-controlSessionCache";
	/**
	 * 用户sessionControl的缓存
	 */
	protected Cache<String, Map<Serializable, SessionControl>> sessionControlCache;

	protected CacheManager cacheManager;
	
	protected String sessionControlCacheName = CREDENTIALS_RETRY_CACHE_NAME;
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request,
			ServletResponse response, Object mappedValue) throws Exception {
		//没有登录的情况下直接pass该过滤器
		return !getSubject(request, response).isAuthenticated();
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request,
			ServletResponse response) throws Exception {
		if(cacheManager == null){
			throw new AuthenticationException("cacheManager must be set for this filter");
		}
		if(this.sessionControlCache == null){
			sessionControlCache = cacheManager.getCache(getSessionControlCacheName());
		}
		Subject subject = getSubject(request, response);
        Session session = subject.getSession();
        Serializable sessionId = session.getId();
        SessionControl sessionControl = new SessionControl(sessionId,SessionControl.STATE_VALID);
        Map<Serializable, SessionControl> sessionControlMap = sessionControlCache.get(getSessionControlCacheKey(subject.getPrincipal()));
        //new Hashtable<Serializable, SessionControl>();
        /**如果缓存为空，则说明该用户首次登录或则是只有它登录*/
        if(sessionControlMap == null || sessionControlMap.isEmpty()) {
        	sessionControlMap = new Hashtable<Serializable, SessionControl>();
        	sessionControlMap.put(sessionId, sessionControl);
        	sessionControlCache.put(getSessionControlCacheKey(subject.getPrincipal()), sessionControlMap);
        	return true;
        }
        /**如果缓存不为空，则说明有该用户之前登录，需要判断当前session是否存在缓存中
         * 如果存在则说明就是缓存中的用户，无需操作，如果不存在，则说明是当前用户新的登录状态，
         * 需要将当前session状态信息放入缓存中，并将之前登录的session状态修改该INVALIDA*/
        if(!sessionControlMap.containsKey(sessionId)) {
        	Set<Serializable> keySet = sessionControlMap.keySet();
            Iterator<Serializable> iterator = keySet.iterator();
        	//如果存在其他已登录会话，则踢出：设置状态为：INVALID
        	while(iterator.hasNext()){
        		SessionControl logged = sessionControlMap.get(iterator.next());
        		logged.setState(SessionControl.STATE_INVALID);
        	}
        	//压入新的会话控制
        	sessionControlMap.put(sessionId, sessionControl);
        	return true;
        }
        /**判断当前session是否不合法，不合法就强制登出*/
        sessionControl = sessionControlMap.get(sessionId);
        if (sessionControl==null || SessionControl.STATE_INVALID.equals(sessionControl.getState())) {
            try {
            	sessionControlMap.remove(sessionId);
                subject.logout();
            } catch (Exception e) {
            	
            }
            saveRequest(request);
            WebUtils.issueRedirect(request, response, getLoginUrl());
            return false;
        }
        
        return true;
	}

	protected abstract String getSessionControlCacheKey(Object principal);

	/**
	 * 设置cache
	 * @param cacheManager
	 */
	public void setCacheManager(CacheManager cacheManager) {
		this.cacheManager = cacheManager;
    }
	 
	public CacheManager getCacheManager() {
		return cacheManager;
	}

	public String getSessionControlCacheName() {
		return sessionControlCacheName;
	}

	public void setSessionControlCacheName(String sessionControlCacheName) {
		this.sessionControlCacheName = sessionControlCacheName;
	}
	
}
