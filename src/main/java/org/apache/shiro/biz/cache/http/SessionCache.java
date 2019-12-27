/*
 * Copyright (c) 2018 (https://github.com/hiwepy).
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
package org.apache.shiro.biz.cache.http;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SESSION缓存管理类
 */
public class SessionCache<K, V> implements Cache<K, V> {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	private String cacheKeyName = null;

	public SessionCache(String cacheKeyName) {
		this.cacheKeyName = cacheKeyName;
	}
	
	public Session getSession(){
		Session session = null;
		try{
			Subject subject = SecurityUtils.getSubject();
			session = subject.getSession(false);
			if (session == null){
				session = subject.getSession();
			}
		}catch (InvalidSessionException e){
			logger.error("Invalid session error", e);
		}catch (UnavailableSecurityManagerException e2){
			logger.error("Unavailable SecurityManager error", e2);
		}
		return session;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public V get(K key) throws CacheException {
		if (key == null){
			return null;
		}
		
		V v = null;
		
		Subject subject = SecurityUtils.getSubject();
		HttpServletRequest request = WebUtils.getHttpRequest(subject);
		
		if (request != null){
			v = (V)request.getAttribute(cacheKeyName);
			if (v != null){
				return v;
			}
		}
		
		V value = null;
		value = (V)getSession().getAttribute(cacheKeyName);
		logger.debug("get {} {} {}", cacheKeyName, key, request != null ? request.getRequestURI() : "");
		
		if (request != null && value != null){
			request.setAttribute(cacheKeyName, value);
		}
		return value;
	}

	@Override
	public V put(K key, V value) throws CacheException {
		if (key == null){
			return null;
		}

		getSession().setAttribute(cacheKeyName, value);
		
		if (logger.isDebugEnabled()){
			Subject subject = SecurityUtils.getSubject();
			HttpServletRequest request = WebUtils.getHttpRequest(subject);
			logger.debug("put {} {} {}", cacheKeyName, key, request != null ? request.getRequestURI() : "");
		}
		
		return value;
	}

	@SuppressWarnings("unchecked")
	@Override
	public V remove(K key) throws CacheException {
		
		V value = null;
		value = (V)getSession().removeAttribute(cacheKeyName);
		logger.debug("remove {} {}", cacheKeyName, key);
		
		return value;
	}

	@Override
	public void clear() throws CacheException {
		getSession().removeAttribute(cacheKeyName);
		logger.debug("clear {}", cacheKeyName);
	}

	@Override
	public int size() {
		logger.debug("invoke session size abstract size method not supported.");
		return 0;
	}

	@Override
	public Set<K> keys() {
		logger.debug("invoke session keys abstract size method not supported.");
		return new HashSet<K>();
	}

	@Override
	public Collection<V> values() {
		logger.debug("invoke session values abstract size method not supported.");
		return Collections.emptyList();
	}
	
	
	
}
