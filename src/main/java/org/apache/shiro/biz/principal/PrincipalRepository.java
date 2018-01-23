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
package org.apache.shiro.biz.principal;

import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.DelegateAuthenticationInfo;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;

/**
 * 
 * @className	： PrincipalRepository
 * @description	： 认证主体信息提供者接口
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年8月26日 下午10:31:02
 * @version 	V1.0
 */
public interface PrincipalRepository {

	/**
	 * 
	 * @description	： 用户信息
	 * @author 		： <a href="https://github.com/vindell">vindell</a>
	 * @date 		：2017年8月26日 下午10:31:34
	 * @param token
	 * @return
	 * @throws AuthenticationException
	 */
	DelegateAuthenticationInfo getAuthenticationInfo(DelegateAuthenticationToken token) throws AuthenticationException;
    
	/**
     * 
     * @description	： 用户角色列表
     * @author 		： <a href="https://github.com/vindell">vindell</a>
     * @date 		：2017年8月26日 下午10:32:12
     * @param principal
     * @return
     */
    Set<String> getRoles(Object principal);
    
    /**
     * 
     * @description	： 用户角色列表【多realms认证的情况下使用】
     * @author 		： <a href="https://github.com/vindell">vindell</a>
     * @date 		：2017年8月26日 下午10:32:35
     * @param principals
     * @return
     */
    Set<String> getRoles(Set<Object> principals);

    /**
     * 
     * @description	： 用户权限列表
     * @author 		： <a href="https://github.com/vindell">vindell</a>
     * @date 		：2017年8月26日 下午10:31:59
     * @param principal
     * @return
     */
    Set<String> getPermissions(Object principal);
    
    /**
     * 
     * @description	： 用户权限列表【多realms认证的情况下使用】
     * @author 		： <a href="https://github.com/vindell">vindell</a>
     * @date 		：2017年8月26日 下午10:32:50
     * @param principals
     * @return
     */
    Set<String> getPermissions(Set<Object> principals);
    
	
}
