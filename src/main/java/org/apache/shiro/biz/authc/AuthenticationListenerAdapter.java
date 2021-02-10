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
package org.apache.shiro.biz.authc;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationListener;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.core.Ordered;

/**
 * Simple adapter implementation of the {@link AuthenticationListener} interface, effectively providing
 * no-op implementations of all methods.
 */
public class AuthenticationListenerAdapter implements AuthenticationListener, Ordered {

	@Override
	public void onSuccess(AuthenticationToken token, AuthenticationInfo info) {
		
	}

	@Override
	public void onFailure(AuthenticationToken token, AuthenticationException ae) {
		
	}

	@Override
	public void onLogout(PrincipalCollection principals) {
		
	}

	public int getOrder() {
		return Integer.MIN_VALUE;
	}
	
}
