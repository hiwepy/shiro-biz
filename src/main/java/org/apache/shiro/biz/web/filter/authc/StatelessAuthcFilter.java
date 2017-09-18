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
package org.apache.shiro.biz.web.filter.authc;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.biz.authc.token.StatelessToken;
import org.apache.shiro.biz.web.Constants;
import org.apache.shiro.web.filter.AccessControlFilter;

/**
 * http://jinnianshilongnian.iteye.com/blog/2041909
 */
public class StatelessAuthcFilter extends AccessControlFilter {
	
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		return false;
	}

	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		// 1、客户端生成的消息摘要
		String clientDigest = request.getParameter(Constants.PARAM_DIGEST);
		// 2、客户端传入的用户身份
		String username = request.getParameter(Constants.PARAM_USERNAME);
		// 3、客户端请求的参数列表
		Map<String, String[]> params = new HashMap<String, String[]>(request.getParameterMap());
		params.remove(Constants.PARAM_DIGEST);
		// 4、生成无状态Token
		StatelessToken token = new StatelessToken(username, params, clientDigest);
		try {
			// 5、委托给Realm进行登录
			getSubject(request, response).login(token);
		} catch (Exception e) {
			e.printStackTrace();
			onLoginFail(response); // 6、登录失败
			return false;
		}
		return true;
	}

	// 登录失败时默认返回401状态码
	private void onLoginFail(ServletResponse response) throws IOException {
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		httpResponse.getWriter().write("login error");
	}
}