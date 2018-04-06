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
package org.apache.shiro.biz.authc.pam;

import java.util.Map;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.biz.authc.token.DefaultAuthenticationToken;
import org.apache.shiro.biz.authc.token.LoginType;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.util.CollectionUtils;

public class DefaultModularRealmAuthenticator extends ModularRealmAuthenticator {

	private Map<String, Object> definedRealms;
	
	/**
	 * 判断登录类型执行操作
	 */
	@Override
	protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken)
			throws AuthenticationException {
		
		this.assertRealmsConfigured();
	
		DefaultAuthenticationToken token = (DefaultAuthenticationToken) authenticationToken;
		/**
		 * 登录类型枚举；1：系统正常登录；2：外部单点登录；3：外部票据登录（通过握手秘钥等参数认证登录）
		 */
		LoginType loginType = token.getLoginType();
		
		Realm realm = (Realm) this.definedRealms.get(loginType.getRealmName());
		
		if (realm == null) {
			return null;
		}

		return this.doSingleRealmAuthentication(realm, authenticationToken);
	}
	
	/**
	 * 判断realm是否为空
	 */
	@Override
	protected void assertRealmsConfigured() throws IllegalStateException {
		this.definedRealms = this.getDefinedRealms();
		if (CollectionUtils.isEmpty(this.definedRealms)) {
            String msg = "Configuration error:  No realms have been configured!  One or more realms must be " +
                    "present to execute an authentication attempt.";
            throw new IllegalStateException(msg);
        }
	}

	public Map<String, Object> getDefinedRealms() {
		return this.definedRealms;
	}

	public void setDefinedRealms(Map<String, Object> definedRealms) {
		this.definedRealms = definedRealms;
	}

}
