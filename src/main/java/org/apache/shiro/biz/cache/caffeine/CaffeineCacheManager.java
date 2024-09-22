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
package org.apache.shiro.biz.cache.caffeine;


import com.github.benmanes.caffeine.cache.LoadingCache;
import org.apache.shiro.cache.AbstractCacheManager;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.lang.util.Destroyable;

public class CaffeineCacheManager extends AbstractCacheManager implements Destroyable {

	protected LoadingCache<String, Object> cache;

	public CaffeineCacheManager() {
	}

	public CaffeineCacheManager(LoadingCache<String, Object> cache) {
		this.cache = cache;
	}

	@Override
	public void destroy() throws Exception {
		if (cache != null) {
			this.cache.invalidateAll();;
		}
	}

	@Override
	protected CaffeineCacheWrapper<Object> createCache(String name) throws CacheException {
		return new CaffeineCacheWrapper<Object>(this.cache);
	}

}
