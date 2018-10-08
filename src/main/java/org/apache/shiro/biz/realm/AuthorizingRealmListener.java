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
package org.apache.shiro.biz.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;

public interface AuthorizingRealmListener {

	/**
	 * 当认证失败时调用【报异常或则是查询不到认证信息认为是失败】
	 * @param realm 调用该方法的Realm实现
	 * @param token 认证Token
	 */
	void onFailure(AuthorizingRealm realm, AuthenticationToken token, AuthenticationException ex);
	
	/**
	 * 当认证成功时调用
	 * @param realm 调用该方法的Realm实现
	 * @param info 当前认证信息
	 * @param session {@link Session}对象
	 */
	void onSuccess(AuthorizingRealm realm, AuthenticationInfo info, Session session);
	
}
