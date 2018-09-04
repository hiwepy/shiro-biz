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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.DisabledAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.biz.authc.exception.IncorrectCaptchaException;
import org.apache.shiro.biz.authc.exception.InvalidAccountException;
import org.apache.shiro.biz.authc.exception.NoneRoleException;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.listener.LoginListener;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TrustableRestAuthenticatingFilter extends AbstractAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(TrustableRestAuthenticatingFilter.class);
	/**
	 * 登录回调监听
	 */
	private List<LoginListener> loginListeners;
	
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
				WebUtils.writeJSONString(response, HttpServletResponse.SC_BAD_REQUEST, mString);
				return false;
			}
		} else {
			String mString = "Attempting to access a path which requires authentication.  Forwarding to the "
					+ "Authentication url [" + getLoginUrl() + "]";
			if (LOG.isTraceEnabled()) {
				LOG.trace(mString);
			}
			WebUtils.writeJSONString(response, HttpServletResponse.SC_UNAUTHORIZED, mString);
			return false;
		}
	}
	
    /**
     * 重写成功登录后的响应逻辑：实现JSON信息回写
     */
    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject,
                                     ServletRequest request, ServletResponse response) throws Exception {
    	
    	//调用事件监听器
		if(getLoginListeners() != null && getLoginListeners().size() > 0){
			for (LoginListener loginListener : getLoginListeners()) {
				loginListener.onLoginSuccess(token, subject, request, response);
			}
		}
		
        // 响应成功状态信息
        WebUtils.writeJSONString(response, HttpServletResponse.SC_OK, "Authentication Success.");
        
        //we handled the success , prevent the chain from continuing:
        return false;
    }
    
    /**
     * 重写成功失败后的响应逻辑：增加失败次数记录和实现JSON信息回写
     */
    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                     ServletRequest request, ServletResponse response) {
    	
    	//调用事件监听器
		if(getLoginListeners() != null && getLoginListeners().size() > 0){
			for (LoginListener loginListener : getLoginListeners()) {
				loginListener.onLoginFailure(token, e, request, response);
			}
		}
    			
        if (LOG.isDebugEnabled()) {
        	LOG.debug( "Authentication exception", e );
        }
        setFailureAttribute(request, e);
        setFailureCountAttribute(request, response, e);
        setFailureRespone(token, e, request, response);
        
        return false;
    }

    protected void setFailureRespone(AuthenticationToken token, AuthenticationException e,
            ServletRequest request, ServletResponse response) {

    	 // 响应异常状态信息
    	Map<String, Object> data = new HashMap<String, Object>();
    	data.put("status", HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        // 已经超出了重试限制，需要进行提醒
        if(isOverRetryTimes(request, response)) {
			data.put("message", "Over Maximum number of retry to login.");
			data.put("captcha", "required");
        }
        // 验证码错误
    	else if(e instanceof IncorrectCaptchaException) {
    		data.put("message", "Invalid captcha value.");
			data.put("captcha", "error");
    	}
		// 账号或密码为空
		else if (e instanceof UnknownAccountException) {
			data.put("message", "Username or password is required.");
		}
		// 账户或密码错误
		else if (e instanceof InvalidAccountException) {
			data.put("message", "Username or password is incorrect, please re-enter.");
		}
		// 账户没有启用
		else if (e instanceof DisabledAccountException) {
			data.put("message", "Account is disabled.");
		}
		// 该用户无所属角色，禁止登录
		else if (e instanceof NoneRoleException) {
			data.put("message", "Username or password is incorrect, please re-enter");
		}
		else {
        	data.put("message", "Authentication Exception.");
        }
        // 导致异常的类型
        data.put(getFailureKeyAttribute(), e.getClass().getName());
        WebUtils.writeJSONString(response, data);
		
	}

    
	public List<LoginListener> getLoginListeners() {
		return loginListeners;
	}

	public void setLoginListeners(List<LoginListener> loginListeners) {
		this.loginListeners = loginListeners;
	}
    
}
