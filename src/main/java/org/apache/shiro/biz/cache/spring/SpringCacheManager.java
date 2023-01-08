/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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
package org.apache.shiro.biz.cache.spring;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Spring CacheManager Wrapper
 * @author wangjie (https://github.com/wj596)
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings({ "unchecked", "rawtypes" })
public class SpringCacheManager implements CacheManager {

	private final org.springframework.cache.CacheManager delegator;
	private final ConcurrentMap<String, SpringCache> CACHES = new ConcurrentHashMap<String, SpringCache>();
	
	public SpringCacheManager(org.springframework.cache.CacheManager cacheManager){
		this.delegator = cacheManager;
	}
	
	@Override
	public <K, V> Cache<K, V> getCache(String cacheName) throws CacheException {
		SpringCache<K,V> cache = this.CACHES.get(cacheName);
		if (cache != null) {
			return cache;
		}
		else {
			synchronized (this.CACHES) {
				cache = this.CACHES.get(cacheName);
				if (cache == null) {
					org.springframework.cache.Cache springCache = this.delegator.getCache(cacheName);
					cache = new SpringCache(cacheName,springCache);
					this.CACHES.put(cacheName, cache);
				}
				return cache;
			}
		}
	}

}
