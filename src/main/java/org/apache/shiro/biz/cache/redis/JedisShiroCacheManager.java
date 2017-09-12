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
package org.apache.shiro.biz.cache.redis;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.biz.cache.ShiroCacheManager;
import org.apache.shiro.biz.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JedisShiroCacheManager implements ShiroCacheManager {

	protected static final Logger LOG = LoggerFactory.getLogger(JedisShiroCacheManager.class);

	// fast lookup by name map
	@SuppressWarnings("rawtypes")
	protected final ConcurrentMap<String, Cache> COMPLIED_CACHE = new ConcurrentHashMap<String, Cache>();

	protected RedisManager redisManager;
	
	/** 
     * The Redis key prefix for caches  
     */  
	protected String keyPrefix = "shiro_redis_cache:";  
      
	@Override
	public void init() {
		// initialize the Redis manager instance  
		redisManager.init();
	}

	@Override
	@SuppressWarnings("unchecked")
	public <K, V> Cache<K, V> getCache(String name) throws CacheException {
		if (!StringUtils.isEmpty(name)) {
			LOG.debug("获取名称为: " + name + " 的JedisShiroCache实例."); 
			Cache<K, V> ret = COMPLIED_CACHE.get(name);
 			if (ret != null) {
 				return ret;
 			} 
 			// Create a new cache instance 
 			ret = new RedisCache<K, V>(redisManager, keyPrefix);
 			// add it to the cache collection
 			Cache<K, V> existing = COMPLIED_CACHE.putIfAbsent(name, ret);
 			if (existing != null) {
 				ret = existing;
 			}
 			return ret;
 		}
 		return null;
	}

	@Override
	public void destroy() {
		redisManager.flushDB();
	}
	
	 /** 
     * Returns the Redis session keys 
     * prefix. 
     * @return The prefix 
     */  
    public String getKeyPrefix() {  
        return keyPrefix;  
    }  
  
    /** 
     * Sets the Redis sessions key  
     * prefix. 
     * @param keyPrefix The prefix 
     */  
    public void setKeyPrefix(String keyPrefix) {  
        this.keyPrefix = keyPrefix;  
    }  
    
	public RedisManager getRedisManager() {
		return redisManager;
	}

	public void setRedisManager(RedisManager redisManager) {
		this.redisManager = redisManager;
	}

}