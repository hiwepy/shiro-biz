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
package org.apache.shiro.biz.auth.credentials;

import java.util.concurrent.atomic.AtomicInteger;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;

/**
 * 
 * @className	： RetryLimitHashedCredentialsMatcher
 * @description	： 密码校验器，支持重复提交次数校验，防范暴力破解
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年7月28日 下午9:56:44
 * @version 	V1.0
 */
public class RetryLimitHashedCredentialsMatcher extends HashedCredentialsMatcher {

    private static final String DEFAULT_CREDENTIALS_RETRY_CACHE_NAME = "SHIRO_CREDENTIALS_RETRY_CACHE";

	private static final int DEFALUE_CREDENTIALS_RETRY_LIMIT = 5;
	
	/**
     * 密码重试次数
     */
	protected int retryLimit = DEFALUE_CREDENTIALS_RETRY_LIMIT;

	protected String credentialsRetryCacheName = DEFAULT_CREDENTIALS_RETRY_CACHE_NAME;
	/**
	 * 缓存支持
	 */
	protected CacheManager cacheManager;

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
    	
    	Cache<Object, AtomicInteger> credentialsRetryCache = getCacheManager().getCache(getCredentialsRetryCacheName());
		AtomicInteger retryCount = credentialsRetryCache.get(token.getPrincipal());
		if (retryCount == null) {
			retryCount = new AtomicInteger(0);
			credentialsRetryCache.put(token.getPrincipal(), retryCount);
		}
		
		//retry count + 1
		if (retryCount.incrementAndGet() > getRetryLimit()) {
			throw new ExcessiveAttemptsException();
		}
		
		boolean matches = super.doCredentialsMatch(token, info);
        if(matches) {
            //clear retry count
        	credentialsRetryCache.remove(token.getPrincipal());
        }
        return matches;
        
    }
    

	public int getRetryLimit() {
		return retryLimit;
	}

	public void setRetryLimit(int retryLimit) {
		this.retryLimit = retryLimit;
	}

	public String getCredentialsRetryCacheName() {
		return credentialsRetryCacheName;
	}

	public void setCredentialsRetryCacheName(String credentialsRetryCacheName) {
		this.credentialsRetryCacheName = credentialsRetryCacheName;
	}

	public CacheManager getCacheManager() {
		return cacheManager;
	}

	public void setCacheManager(CacheManager cacheManager) {
		this.cacheManager = cacheManager;
	}
	
}
