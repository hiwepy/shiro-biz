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
package org.apache.shiro.biz.auth.realm;


/**
 * 
 * @className	： RedisAuthorizingRealm
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年9月12日 下午10:47:42
 * @version 	V1.0
 */
public class RedisAuthorizingRealm {

	/*protected AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {    
        
        if (principals == null) {    
            return null;    
        }    
    
        AuthorizationInfo info = null;    
    
        if (log.isTraceEnabled()) {    
            log.trace("Retrieving AuthorizationInfo for principals [" + principals + "]");    
        }    
    
        Cache<Object, AuthorizationInfo> cache = getAvailableAuthorizationCache();    
        if (cache != null) {    
            if (log.isTraceEnabled()) {    
                log.trace("Attempting to retrieve the AuthorizationInfo from cache.");    
            }    
            Object key = getAuthorizationCacheKey(principals);    
            info = cache.get(key);    
            if (log.isTraceEnabled()) {    
                if (info == null) {    
                    log.trace("No AuthorizationInfo found in cache for principals [" + principals + "]");    
                } else {    
                    log.trace("AuthorizationInfo found in cache for principals [" + principals + "]");    
                }    
            }    
        }    
        if (info == null) {    
            // Call template method if the info was not found in a cache     
            info = doGetAuthorizationInfo(principals);    
            // If the info is not null and the cache has been created, then cache the authorization info.     
            if (info != null && cache != null) {    
                if (log.isTraceEnabled()) {    
                    log.trace("Caching authorization info for principals: [" + principals + "].");    
                }    
                Object key = getAuthorizationCacheKey(principals);    
                cache.put(key, info);    
            }    
        }    
        return info;    
    } 
	*/
}
