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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TrustableFormAuthenticatingFilter extends AbstractAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(TrustableFormAuthenticatingFilter.class);
	
	/**
	 * 是否重定向到前一个访问地址
	 */
	private boolean redirectToSavedRequest;
	/**
	 * 登录回调监听
	 */
	private List<LoginListener> loginListeners;
	
	public TrustableFormAuthenticatingFilter() {
		super();
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
	
	/**
     * 重写成功失败后的响应逻辑：增加失败次数记录
     */
    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                     ServletRequest request, ServletResponse response) {
        if (LOG.isDebugEnabled()) {
        	LOG.debug( "Authentication exception", e );
        }
        setFailureAttribute(request, e);
        setFailureCountAttribute(request, response, e);
        // 已经超出了重试限制，需要进行提醒
        if(isOverRetryTimes(request, response)) {
        	WebUtils.getHttpRequest(request).setAttribute("captcha", "required");
        }
        
        //login failed, let request continue back to the login page:
        return true;
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
