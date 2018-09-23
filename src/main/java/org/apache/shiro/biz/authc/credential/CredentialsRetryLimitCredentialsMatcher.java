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
package org.apache.shiro.biz.authc.credential;

import java.util.concurrent.atomic.AtomicInteger;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;

/**
 * 密码校验器，支持重复提交次数校验，防范暴力破解
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class CredentialsRetryLimitCredentialsMatcher extends HashedCredentialsMatcher {

    /**
     * The default active retry times cache name, equal to {@code shiro-activeSessionCache}.
     */
    public static final String CREDENTIALS_RETRY_CACHE_NAME = "shiro-credentialsRetryCache";

    public static final int CREDENTIALS_RETRY_TIMES_LIMIT = 5;
	
    /**
     * The CacheManager to use to acquire the retry times.
     */
    private CacheManager cacheManager;
    /**
     * The Cache instance responsible for caching retry times.
     */
    private Cache<Object, AtomicInteger> credentialsRetryTimes;
	/**
     * The credentials retry limit, defaults to {@link #CREDENTIALS_RETRY_TIMES_LIMIT}.
     */
	protected int credentialsRetryTimesLimit = CREDENTIALS_RETRY_TIMES_LIMIT;
	 /**
     * The name of the retry times, defaults to {@link #CREDENTIALS_RETRY_CACHE_NAME}.
     */
	protected String credentialsRetryCacheName = CREDENTIALS_RETRY_CACHE_NAME;

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		
		AtomicInteger retryCount = getCachedRetryTimes(token.getPrincipal());
		if (retryCount == null) {
			retryCount = new AtomicInteger(0);
			getCredentialsRetryCacheLazy().put(token.getPrincipal(), retryCount);
		}
		
		//retry count + 1
		if (retryCount.incrementAndGet() > getCredentialsRetryTimesLimit()) {
			throw new ExcessiveAttemptsException();
		}
		
		boolean matches = super.doCredentialsMatch(token, info);
        if(matches) {
            //clear retry count
        	getCredentialsRetryCacheLazy().remove(token.getPrincipal());
        }
        return matches;
        
    }
    

    /**
     * Sets the cacheManager to use for acquiring the {@link #getActiveSessionsCache() activeSessionsCache} if
     * one is not configured.
     *
     * @param cacheManager the manager to use for constructing the session cache.
     */
    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    /**
     * Returns the CacheManager to use for acquiring the {@link #getActiveSessionsCache() activeSessionsCache} if
     * one is not configured.  That is, the {@code CacheManager} will only be used if the
     * {@link #getActiveSessionsCache() activeSessionsCache} property is {@code null}.
     *
     * @return the CacheManager used by the implementation that creates the activeSessions Cache.
     */
    public CacheManager getCacheManager() {
        return cacheManager;
    }
    
	public int getCredentialsRetryTimesLimit() {
		return credentialsRetryTimesLimit;
	}

	public void setCredentialsRetryTimesLimit(int credentialsRetryTimesLimit) {
		this.credentialsRetryTimesLimit = credentialsRetryTimesLimit;
	}

	public String getCredentialsRetryCacheName() {
		return credentialsRetryCacheName;
	}

	public void setCredentialsRetryCacheName(String credentialsRetryCacheName) {
		this.credentialsRetryCacheName = credentialsRetryCacheName;
	}
	
	public void setCredentialsRetryTimes(Cache<Object, AtomicInteger> credentialsRetryTimes) {
		this.credentialsRetryTimes = credentialsRetryTimes;
	}

	private Cache<Object, AtomicInteger> getCredentialsRetryCacheLazy() {
        if (this.credentialsRetryTimes == null) {
            this.credentialsRetryTimes = createCredentialsRetryCache();
        }
        return credentialsRetryTimes;
    }

    protected Cache<Object, AtomicInteger> createCredentialsRetryCache() {
        Cache<Object, AtomicInteger> cache = null;
        CacheManager mgr = getCacheManager();
        if (mgr != null) {
            String name = getCredentialsRetryCacheName();
            cache = mgr.getCache(name);
        }
        return cache;
    }
    
    protected AtomicInteger getCachedRetryTimes(Object principal) {
    	AtomicInteger cached = null;
        if (principal != null) {
            Cache<Object, AtomicInteger> cache = getCredentialsRetryCacheLazy();
            if (cache != null) {
                cached = getCachedRetryTimes(principal, cache);
            }
        }
        return cached;
    }
    
    protected AtomicInteger getCachedRetryTimes(Object principal, Cache<Object, AtomicInteger> cache) {
        return cache.get(principal);
    }
	
}
