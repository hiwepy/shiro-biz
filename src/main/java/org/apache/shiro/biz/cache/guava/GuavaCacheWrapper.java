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
package org.apache.shiro.biz.cache.guava;


import java.util.Collection;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;

import com.google.common.cache.LoadingCache;

/**
 * Guava Cache Wrapper
 */
public class GuavaCacheWrapper<V> implements Cache<String, V> {
	
	protected LoadingCache<String, V> cache;
	
	public GuavaCacheWrapper( LoadingCache<String, V> cache) {
		this.cache = cache;
	}
	
	@Override
	public V get(String key) throws CacheException {
		try {
			return (V) this.cache.get(key);
		} catch (ExecutionException e) {
			throw new CacheException(e);
		}
	}
	
	@Override
	public V put(String key, V value) throws CacheException {
		this.cache.put(key, value);
		return value;
	}
	
	@Override
	public V remove(String key) throws CacheException {
		this.cache.invalidate(key);
		return null;
	}
	
	@Override
	public void clear() throws CacheException {
		this.cache.invalidateAll();
	}
	
	@Override
	public int size() {
		return Long.valueOf(this.cache.size()).intValue();
	}
	
	@Override
	public Set<String> keys() {
		return this.cache.asMap().keySet();
	}
	
	@Override
	public Collection<V> values() {
		return this.cache.asMap().values();
	}

}
