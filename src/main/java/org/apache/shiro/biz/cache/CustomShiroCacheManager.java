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
package org.apache.shiro.biz.cache;

import org.apache.shiro.ShiroException;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Initializable;
 
public class CustomShiroCacheManager implements CacheManager, Destroyable , Initializable {
 
    private ShiroCacheManager shrioCacheManager;
 
    public ShiroCacheManager getShrioCacheManager() {
        return shrioCacheManager;
    }
 
    public void setShrioCacheManager(ShiroCacheManager shrioCacheManager) {
        this.shrioCacheManager = shrioCacheManager;
    }
 
    @Override
	public void init() throws ShiroException {
    	getShrioCacheManager().init();
	}
 
    /*
     * 根据缓存名字获取一个Cache
     */
    @Override
    public <K, V> Cache<K, V> getCache(String name) throws CacheException {
        return getShrioCacheManager().getCache(name);
    }

    @Override
    public void destroy() throws Exception {
        getShrioCacheManager().destroy();
    }
 
}