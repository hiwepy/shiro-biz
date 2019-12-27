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


import org.apache.shiro.cache.AbstractCacheManager;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.util.Destroyable;

import com.google.common.cache.LoadingCache;

public class GuavaCacheManager extends AbstractCacheManager implements Destroyable {
	
	protected LoadingCache<String, Object> cache;

	public GuavaCacheManager() {
	}
	
	public GuavaCacheManager(LoadingCache<String, Object> cache) {
		this.cache = cache;
	}

	@Override
	public void destroy() throws Exception {
		if (cache != null) {
			this.cache.invalidateAll();;
		}
	}

	@Override
	protected GuavaCacheWrapper<Object> createCache(String name) throws CacheException {
		return new GuavaCacheWrapper<Object>(this.cache);
	}

}
