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
package org.apache.shiro.biz.web.filter;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Deque;
import java.util.LinkedList;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.web.Constants;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.SimpleOnlineSession;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;

/**
 *  <p>cacheManager：使用cacheManager获取相应的cache来缓存用户登录的会话；用于保存用户—会话之间的关系的；</p>
 *	<p>sessionManager：用于根据会话ID，获取会话进行踢出操作的；</p>
 *	<p>kickoutAfter：是否踢出后来登录的，默认是false；即后者登录的用户踢出前者登录的用户；</p>
 *	<p>maxSession：同一个用户最大的会话数，默认1；比如2的意思是同一个用户允许最多同时两个人登录；</p>
 *	<p>kickoutUrl：被踢出后重定向到的地址；</p>
 *  <p>部分资料来自：http://jinnianshilongnian.iteye.com/blog/2039760 </p>
 */
public abstract class HttpServletSessionDequeFilter extends AccessControlFilter {

    /**
     * The default redirect URL to where the user will be redirected after kickout.  The value is {@code "/"}, Shiro's
     * representation of the web application's context root.
     */
    public static final String DEFAULT_REDIRECT_URL = "/";
    public static final String DEFAULT_SESSION_DEQUE_CACHE_NAME = "shiro-sessionDequeCache";
    
    /** User login status cache */
    private Cache<String, Deque<Serializable>> sessionDequeCache;
    /** cacheManager */
    private CacheManager cacheManager;
    /** sessionManager */
	private SessionManager sessionManager;
	
	/** Whether to kickout the first login session. */
    private boolean kickoutFirst = false;
    /** Maximum number of sessions for the same account . */
	private int sessionMaximumKickout = 1;
	private String sessionDequeCacheName = DEFAULT_SESSION_DEQUE_CACHE_NAME;
    /** he URL to where the user will be redirected after kickout. */
    private String redirectUrl = DEFAULT_REDIRECT_URL;
    
    @Override
	protected boolean isAccessAllowed(ServletRequest request,
			ServletResponse response, Object mappedValue) {
    	
    	Subject subject = getSubject(request, response);
        if(!subject.isAuthenticated() && !subject.isRemembered()) {
            //如果没有登录，直接进行之后的流程
            return true;
        }
		return false;
	}
    
	protected abstract String getSessionDequeCacheKey(Object principal);
    
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
       
    	if(cacheManager == null){
			throw new AuthenticationException("cacheManager must be set for this filter");
		}
    	
    	if(this.sessionDequeCache == null){
    		this.sessionDequeCache = getCacheManager().getCache(getSessionDequeCacheName());
		}
    	
    	Subject subject = getSubject(request, response);
        Session session = subject.getSession();
        Serializable sessionId = session.getId();

        // 同步控制
        String cacheKey = getSessionDequeCacheKey(subject.getPrincipal());
        Deque<Serializable> deque = sessionDequeCache.get(cacheKey);
        if(deque == null) {
            deque = new LinkedList<Serializable>();
            sessionDequeCache.put(cacheKey, deque);
        }

        //如果队列里没有此sessionId，且用户没有被踢出；放入队列
        if(!deque.contains(sessionId) && session.getAttribute(Constants.SESSION_KICKOUT_KEY) == null) {
            deque.push(sessionId);
        }

        // 如果队列里的sessionId数超出最大会话数，开始强制下线
        while(deque.size() > getSessionMaximumKickout()) {
            Serializable kickoutSessionId = null;
            // 踢出最早登录的会话
            if(isKickoutFirst()) { 
                kickoutSessionId = deque.removeFirst();
            }
            // 踢出最后登录的会话
            else { 
                kickoutSessionId = deque.removeLast();
            }
            try {
            	// 可能为空或失效
                Session kickoutSession = getSessionManager().getSession(new DefaultSessionKey(kickoutSessionId));
                if (kickoutSession != null) {
                	//设置会话的kickout属性标记
                    kickoutSession.setAttribute(Constants.SESSION_KICKOUT_KEY, true);
                	if(kickoutSession instanceof SimpleOnlineSession) {
                		SimpleOnlineSession onlineSession = (SimpleOnlineSession) session;
                		onlineSession.setStatus(SimpleOnlineSession.OnlineStatus.force_logout);
                	}
                }
            } catch (Exception e) {
            	//ignore exception
            }
        }

        //如果被踢出了，直接退出，重定向到踢出后的地址
        if (session.getAttribute(Constants.SESSION_KICKOUT_KEY) != null) {
            try {
            	//会话被踢出：注销登录状态
                subject.logout();
            } catch (Exception e) { //ignore
            }
            saveRequest(request);
            // 检查是否相对目录
            boolean contextRelative = true;
            if(escapeURL(getRedirectUrl()).contains(escapeURL(request.getScheme() + "://" + request.getServerName() ))){
            	contextRelative = false;
            }
            WebUtils.issueRedirect(request, response, getRedirectUrl(), null, contextRelative);
            return false;
        }

        return true;
    }
    

    public String escapeURL(String url) {
        String ret = "";
        try {
            ret = URLEncoder.encode(url, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return ret;
    }
    
    public SessionManager getSessionManager() {
		return sessionManager;
	}

	public void setSessionManager(SessionManager sessionManager) {
		this.sessionManager = sessionManager;
	}

	public boolean isKickoutFirst() {
		return kickoutFirst;
	}

	public void setKickoutFirst(boolean kickoutFirst) {
		this.kickoutFirst = kickoutFirst;
	}

	public int getSessionMaximumKickout() {
		return sessionMaximumKickout;
	}

	public void setSessionMaximumKickout(int sessionMaximumKickout) {
		this.sessionMaximumKickout = sessionMaximumKickout;
	}

	public void setCacheManager(CacheManager cacheManager) {
		this.cacheManager = cacheManager;
    }
	 
	public CacheManager getCacheManager() {
		return cacheManager;
	}

	public String getSessionDequeCacheName() {
		return sessionDequeCacheName;
	}

	public void setSessionDequeCacheName(String sessionDequeCacheName) {
		this.sessionDequeCacheName = sessionDequeCacheName;
	}

	public String getRedirectUrl() {
		return redirectUrl;
	}

	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}
	
}
