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
package org.apache.shiro.biz.web.filter.authc;

import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;

public class TraceableFormAuthenticationFilter extends TrustableFormAuthenticationFilter {

	/**
	 * 登录回调监听
	 */
	private List<LoginListener> loginListeners;
	/**
	 * 是否重定向到前一个访问地址
	 */
	private boolean redirectToSavedRequest;
	
	@Override
	protected boolean isLoginSubmission(ServletRequest request, ServletResponse response) {
		return (request instanceof HttpServletRequest) ;
	}
	
	@Override
	protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request,
			ServletResponse response) {
		//调用事件监听器
		if(getLoginListeners() != null && getLoginListeners().size() > 0){
			for (LoginListener loginListener : getLoginListeners()) {
				loginListener.onLoginFailure(token, e, request, response);
			}
		}
		return super.onLoginFailure(token, e, request, response);
	}
	
	@Override
	protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {
		//调用事件监听器
		if(getLoginListeners() != null && getLoginListeners().size() > 0){
			for (LoginListener loginListener : getLoginListeners()) {
				loginListener.onLoginSuccess(token, subject, request, response);
			}
		}
		
		if(isRedirectToSavedRequest()) {
			issueSuccessRedirect(request, response);
		} else {
			 WebUtils.issueRedirect(request, response, getSuccessUrl());
		}
		 
		//we handled the success redirect directly, prevent the chain from continuing:
        return false;
	}
	
	public List<LoginListener> getLoginListeners() {
		return loginListeners;
	}
	
	public void setLoginListeners(List<LoginListener> loginListeners) {
		this.loginListeners = loginListeners;
	}

	public boolean isRedirectToSavedRequest() {
		return redirectToSavedRequest;
	}

	public void setRedirectToSavedRequest(boolean redirectToSavedRequest) {
		this.redirectToSavedRequest = redirectToSavedRequest;
	}
	
}
