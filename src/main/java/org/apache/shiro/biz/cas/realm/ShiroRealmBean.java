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
package org.apache.shiro.biz.cas.realm;


import java.util.Iterator;
import java.util.List;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cas.CasRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * 
 * @className	： ShiroRealmBean
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年7月28日 下午10:08:12
 * @version 	V1.0
 */
public class ShiroRealmBean extends CasRealm {
	// 用于获取用户信息及用户权限信息的业务接口
	private ShiroRealmBean permissionMgr;

	// 授权
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		// 权限名称
		String permissionName;
		try {
			// 查询用户授权信息
			SimpleAuthorizationInfo author = new SimpleAuthorizationInfo();
			// 查找登录用户名称
			String username = (String) principals.getPrimaryPrincipal();
			System.out.println(username);
			// 查询用户对应角色对应的资源
			List<String> lstPermission = null;//permissionMgr.queryUserPermission(username);
			// 迭代查询
			Iterator<String> it = lstPermission.iterator();
			while (it.hasNext()) {
				permissionName = it.next().toString();
				// 把资源名称添加到用户所对于的资源集合中
				author.addStringPermission(permissionName);
			}
			return author;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public ShiroRealmBean getPermissionMgr() {
		return permissionMgr;
	}

	public void setPermissionMgr(ShiroRealmBean permissionMgr) {
		this.permissionMgr = permissionMgr;
	}
}