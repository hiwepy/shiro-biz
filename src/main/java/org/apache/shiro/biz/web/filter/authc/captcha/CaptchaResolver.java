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
package org.apache.shiro.biz.web.filter.authc.captcha;

import javax.servlet.ServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.token.CaptchaAuthenticationToken;

public interface CaptchaResolver {

	/**
	 * Valid the current captcha via the given request.
	 * @param request request to be used for resolution
	 * @param token the captcha authentication token
	 * @return the result
	 */
	boolean validCaptcha(ServletRequest request, CaptchaAuthenticationToken token) throws AuthenticationException;
	
}
