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


import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.codec.CodecSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * MD5加密对比, 密码重试限制, 默认是5次
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class DefaultCredentialsMatcher extends CodecSupport implements CredentialsMatcher {

	private static final Logger LOG = LoggerFactory.getLogger(DefaultCredentialsMatcher.class);
	
	private static final String DEFAULT_CREDENTIALS_RETRY_CACHE_NAME = "SHIRO_CREDENTIALS_RETRY_CACHE";

	private static final int DEFALUE_CREDENTIALS_RETRY_LIMIT = 5;

	protected int retryLimit = DEFALUE_CREDENTIALS_RETRY_LIMIT;

	protected String credentialsRetryCacheName = DEFAULT_CREDENTIALS_RETRY_CACHE_NAME;

	protected CacheManager cacheManager;

	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		// check retry
		checkCredentialsRetry(token);
		// credentials match
		boolean matches = credentialsMatch(token, info);
		if (matches) {
			cacheManager.getCache(getCredentialsRetryCacheName()).remove(token.getPrincipal());
		}
		return credentialsMatch(token, info);
	}

	//匹配用户输入的token的凭证（未加密）与系统提供的凭证（已加密） 
	protected boolean credentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		Object tokenCredentials = token.getCredentials();
		Object accountCredentials = info.getCredentials();
		return equals(tokenCredentials, accountCredentials);
	}

	protected boolean equals(Object tokenCredentials, Object accountCredentials) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Performing credentials equality check for tokenCredentials of type ["
					+ tokenCredentials.getClass().getName() + " and accountCredentials of type ["
					+ accountCredentials.getClass().getName() + "]");
		}
		if (isByteSource(tokenCredentials) && isByteSource(accountCredentials)) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Both credentials arguments can be easily converted to byte arrays.  Performing "
						+ "array equals comparison");
			}
			byte[] tokenBytes = toBytes(tokenCredentials);
			byte[] accountBytes = toBytes(accountCredentials);
			return Arrays.equals(tokenBytes, accountBytes);
		} else {
			return accountCredentials.equals(tokenCredentials);
		}
	}

	protected void checkCredentialsRetry(AuthenticationToken token) {
		Cache<Object, AtomicInteger> credentialsRetryCache = cacheManager.getCache(getCredentialsRetryCacheName());
		AtomicInteger retryCount = credentialsRetryCache.get(token.getPrincipal());
		if (retryCount == null) {
			retryCount = new AtomicInteger(0);
			credentialsRetryCache.put(token.getPrincipal(), retryCount);
		}
		if (retryCount.incrementAndGet() > getRetryLimit()) {
			throw new ExcessiveAttemptsException();
		}
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

