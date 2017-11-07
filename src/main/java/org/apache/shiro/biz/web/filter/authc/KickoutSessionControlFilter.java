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

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Deque;
import java.util.LinkedList;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;

/**
 * 
 *  cacheManager：使用cacheManager获取相应的cache来缓存用户登录的会话；用于保存用户—会话之间的关系的；
	sessionManager：用于根据会话ID，获取会话进行踢出操作的；
	kickoutAfter：是否踢出后来登录的，默认是false；即后者登录的用户踢出前者登录的用户；
	maxSession：同一个用户最大的会话数，默认1；比如2的意思是同一个用户允许最多同时两个人登录；
	kickoutUrl：被踢出后重定向到的地址；
 * 
 * @className	： KickoutSessionControlFilter
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年9月16日 下午11:02:46
 * @version 	V1.0
 */
public abstract class KickoutSessionControlFilter extends AccessControlFilter {

    
    public static final String DEFAULT_SESSION_CONTROL_CACHE_NAME = "shiro-kickout-session";
    private String sessionControlCacheName = DEFAULT_SESSION_CONTROL_CACHE_NAME;
    
    /**
  	 * 用户登录状态缓存
  	 */
    private Cache<String, Deque<Serializable>> cache;
    private CacheManager cacheManager;
	private SessionManager sessionManager;
	
	private String kickoutAttr; //Session中的踢出标记
	private String kickoutUrl; //踢出后到的地址
    private boolean kickoutAfter = false; //踢出之前登录的/之后登录的用户 默认踢出之前登录的用户
    private int maxSession = 1; //同一个帐号最大会话数 默认1
	
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
    
	protected abstract String getSessionControlCacheKey(Object principal);
    
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
       
    	if(cacheManager == null){
			throw new AuthenticationException("cacheManager must be set for this filter");
		}
    	
    	if(this.cache == null){
    		this.cache = cacheManager.getCache(getSessionControlCacheName());
		}
    	
    	Subject subject = getSubject(request, response);
        Session session = subject.getSession();
        Serializable sessionId = session.getId();

        // 同步控制
        String username = (String) subject.getPrincipal();
        Deque<Serializable> deque = cache.get(username);
        if(deque == null) {
            deque = new LinkedList<Serializable>();
            cache.put(username, deque);
        }

        //如果队列里没有此sessionId，且用户没有被踢出；放入队列
        if(!deque.contains(sessionId) && session.getAttribute(getKickoutAttr()) == null) {
            deque.push(sessionId);
        }

        //如果队列里的sessionId数超出最大会话数，开始强制下线
        while(deque.size() > getMaxSession()) {
            Serializable kickoutSessionId = null;
            //踢出最早登录的会话
            if(isKickoutAfter()) { 
                kickoutSessionId = deque.removeFirst();
            }
            //踢出最后登录的会话
            else { 
                kickoutSessionId = deque.removeLast();
            }
            try {
                Session kickoutSession = sessionManager.getSession(new DefaultSessionKey(kickoutSessionId));
                if(kickoutSession != null) {
                	//设置会话的kickout属性表示踢出了
                    kickoutSession.setAttribute(getKickoutAttr(), true);
                }
            } catch (Exception e) {
            	//ignore exception
            }
        }

        //如果被踢出了，直接退出，重定向到踢出后的地址
        if (session.getAttribute(getKickoutAttr()) != null) {
            try {
            	//会话被踢出：注销登录状态
                subject.logout();
            } catch (Exception e) { //ignore
            }
            saveRequest(request);
            // 检查是否相对目录
            boolean contextRelative = true;
            if(escapeURL(getKickoutUrl()).contains(escapeURL(request.getScheme() + "://" + request.getServerName() ))){
            	contextRelative = false;
            }
            WebUtils.issueRedirect(request, response, getKickoutUrl(), null, contextRelative);
            
            WebUtils.issueRedirect(request, response, kickoutUrl);
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

	public String getKickoutAttr() {
		return kickoutAttr;
	}

	public void setKickoutAttr(String kickoutAttr) {
		this.kickoutAttr = kickoutAttr;
	}

	public String getKickoutUrl() {
		return kickoutUrl;
	}

	public void setKickoutUrl(String kickoutUrl) {
		this.kickoutUrl = kickoutUrl;
	}

	public boolean isKickoutAfter() {
		return kickoutAfter;
	}

	public void setKickoutAfter(boolean kickoutAfter) {
		this.kickoutAfter = kickoutAfter;
	}

	public int getMaxSession() {
		return maxSession;
	}

	public void setMaxSession(int maxSession) {
		this.maxSession = maxSession;
	}

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
