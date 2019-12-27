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
package org.apache.shiro.biz.web.filter.authc;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.authc.AuthenticationSuccessHandler;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;

public class TrustableRestAuthenticatingFilter extends AbstractTrustableAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(TrustableRestAuthenticatingFilter.class);
	
	
	public TrustableRestAuthenticatingFilter() {
		super();
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		if (isLoginRequest(request, response)) {
			if (isLoginSubmission(request, response)) {
				if (LOG.isTraceEnabled()) {
					LOG.trace("Login submission detected.  Attempting to execute login.");
				}
				return executeLogin(request, response);
			} else {
				String mString = "Authentication url [" + getLoginUrl() + "] Not Http Post request.";
				if (LOG.isTraceEnabled()) {
					LOG.trace(mString);
				}
				
				WebUtils.toHttp(response).setStatus(HttpStatus.SC_BAD_REQUEST);
	    		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
	    		JSONObject.writeJSONString(response.getWriter(), AuthcResponse.fail(mString));
				return false;
			}
		} else {
			
			String mString = "Attempting to access a path which requires authentication.  Request the "
					+ "Authentication url [" + getLoginUrl() + "]";
			if (LOG.isTraceEnabled()) {
				LOG.trace(mString);
			}
			
			// 响应成功状态信息
			WebUtils.toHttp(response).setStatus(HttpStatus.SC_BAD_REQUEST);
    		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
    		JSONObject.writeJSONString(response.getWriter(), AuthcResponse.fail(mString));
			
			return false;
		}
	}
	
    /**
     * Rewrite the response logic after successful login: JSON information write back
     */
    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject,
                                     ServletRequest request, ServletResponse response) throws Exception {
    	
    	// Login Listener
		if(getLoginListeners() != null && getLoginListeners().size() > 0){
			for (LoginListener loginListener : getLoginListeners()) {
				loginListener.onSuccess(token, subject, request, response);
			}
		}
		
		if (CollectionUtils.isEmpty(getSuccessHandlers())) {
			this.writeSuccessString(token, subject, request, response);
		} else {
			boolean isMatched = false;
			for (AuthenticationSuccessHandler successHandler : getSuccessHandlers()) {

				if (successHandler != null && successHandler.supports(token)) {
					successHandler.onAuthenticationSuccess(token, request, response, subject);
					isMatched = true;
					break;
				}
			}
			if (!isMatched) {
				this.writeSuccessString(token, subject, request, response);
			}
		}
        
        //we handled the success , prevent the chain from continuing:
        return false;
    }
   
    
}
