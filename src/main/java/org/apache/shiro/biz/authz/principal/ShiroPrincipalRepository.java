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
package org.apache.shiro.biz.authz.principal;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;

import java.util.Set;

/**
 * 认证主体信息提供者接口
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
public interface ShiroPrincipalRepository  {

	/**
	 * 用户信息
	 * @param token 用于认证的Token
	 * @return 认证信息对象
	 * @throws AuthenticationException 认证异常
	 */
	AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException;
    
	/**
	 * 用户角色列表
	 * @param principal 认证主体对象
	 * @return 角色列表
	 */
	Set<String> getRoles(Object principal);
    
    /**
     * 用户角色列表【多realm认证的情况下使用】
     * @param principals 认证主体对象集合
     * @return 角色列表
     */
	Set<String> getRoles(Set<Object> principals);

    /**
     * 用户权限列表
     * @param principal 认证主体对象
     * @return 权限列表
     */
	Set<String> getPermissions(Object principal);
    
    /**
     * 用户权限列表【多realm认证的情况下使用】
     * @param principals 认证主体对象集合
     * @return 权限列表
     */
	Set<String> getPermissions(Set<Object> principals);
	
	/**
	 * 用户锁定操作
     * @param principal 认证主体对象
	 */
	void doLock(Object principal);
	
	
}
