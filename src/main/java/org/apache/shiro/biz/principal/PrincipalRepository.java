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
package org.apache.shiro.biz.principal;

import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.DelegateAuthenticationInfo;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;

/**
 * 认证主体信息提供者接口
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public interface PrincipalRepository<T extends Principal> {

	/**
	 * 用户信息
	 * @param token 用于认证的Token
	 * @return 委托的认证信息对象
	 * @throws AuthenticationException 认证异常
	 */
	DelegateAuthenticationInfo getAuthenticationInfo(DelegateAuthenticationToken token) throws AuthenticationException;
    
	/**
	 * 用户角色列表
	 * @param principal 认证主体对象
	 * @return 角色列表
	 */
    Set<String> getRoles(T principal);
    
    /**
     * 用户角色列表【多realm认证的情况下使用】
     * @param principals 认证主体对象集合
     * @return 角色列表
     */
    Set<String> getRoles(Set<T> principals);

    /**
     * 用户权限列表
     * @param principal 认证主体对象
     * @return 权限列表
     */
    Set<String> getPermissions(T principal);
    
    /**
     * 用户权限列表【多realm认证的情况下使用】
     * @param principals 认证主体对象集合
     * @return 权限列表
     */
    Set<String> getPermissions(Set<T> principals);
	
}
