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

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.springframework.core.Ordered;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * TODO
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
public interface AuthenticationSuccessHandler extends Ordered{

	public boolean supports(AuthenticationToken token);

	/**
	 * Called when a user has been successfully authenticated.
	 *
	 * @param request        the request which caused the successful authentication
	 * @param response       the response
	 * @param subject the <tt>Subject</tt> object which was created during the authentication process.
	 */
	void onAuthenticationSuccess(AuthenticationToken token, ServletRequest request, ServletResponse response, Subject subject) ;

	default int getOrder() {
		return Integer.MIN_VALUE;
	}
	
}
