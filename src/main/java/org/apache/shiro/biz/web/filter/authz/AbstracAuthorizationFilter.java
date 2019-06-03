/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
package org.apache.shiro.biz.web.filter.authz;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.authz.AuthorizationFailureHandler;
import org.apache.shiro.biz.authz.AuthorizationSuccessHandler;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMethod;

import com.alibaba.fastjson.JSONObject;
import com.google.common.net.HttpHeaders;

/**
 * 抽象的授权 (authorization)过滤器
 * 
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public abstract class AbstracAuthorizationFilter extends AuthorizationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(AbstracAuthorizationFilter.class);
	/** If Session Stateless */
	private boolean sessionStateless = false;
	/** Authorization Success Handler */
	private List<AuthorizationSuccessHandler> successHandlers;
	/** Authorization Failure Handler */
	private List<AuthorizationFailureHandler> failureHandlers;
	
	protected void setHeader(HttpServletResponse response, String key, String value) {
		if(StringUtils.hasText(value)) {
			boolean match = response.getHeaderNames().stream().anyMatch(item -> StringUtils.equalsIgnoreCase(item, key));
			if(!match) {
				response.setHeader(key, value);
				if(LOG.isDebugEnabled()){
					LOG.debug("Filter:{} Set HTTP HEADER: {}:{}.", getName(), key, value);
				}
			}
		}
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		// 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
		if (httpRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
			// 服务器端 Access-Control-Allow-Credentials = true时，参数Access-Control-Allow-Origin 的值不能为 '*' 
			this.setHeader(httpResponse, HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
			this.setHeader(httpResponse, HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, httpRequest.getHeader("Origin"));
			httpResponse.setStatus(HttpServletResponse.SC_OK);
			return false;
		}
		return !isSessionStateless();
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
		Subject subject = getSubject(request, response);
		// 未认证
		if (null == subject.getPrincipal()) {
			// Ajax 请求：响应json数据对象
			if (isSessionStateless() || WebUtils.isAjaxRequest(request)) {
				
				WebUtils.toHttp(response).setStatus(HttpStatus.SC_UNAUTHORIZED);
	    		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
	    		JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error("Unauthentication."));
	    		
				return false;
			}
			// 普通请求：重定向到登录页
			if(isSessionStateless()) {
				redirectToLogin(request, response);
			} else {
				saveRequestAndRedirectToLogin(request, response);
			}
			return false;
		} else {
			if (isSessionStateless() || WebUtils.isAjaxRequest(request)) {
				WebUtils.toHttp(response).setStatus(HttpStatus.SC_FORBIDDEN);
	    		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
	    		JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error("Forbidden."));
				return false;
			} else {
				// If subject is known but not authorized, redirect to the unauthorized URL if
				// there is one
				// If no unauthorized URL is specified, just return an unauthorized HTTP status
				// code
				String unauthorizedUrl = getUnauthorizedUrl();
				// SHIRO-142 - ensure that redirect _or_ error code occurs - both cannot happen
				// due to response commit:
				if (StringUtils.hasText(unauthorizedUrl)) {
					WebUtils.issueRedirect(request, response, unauthorizedUrl);
				} else {
					WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
				}
			}
		}
		return false;
	}
	
	@Override
	protected Subject getSubject(ServletRequest request, ServletResponse response) {
		if(isSessionStateless()) {
			// 重写Subject对象获取逻辑,解决认证信息缓存问题，达到每次认证都是一次新的认证
			Subject subject = (new Subject.Builder()).buildSubject();
	        ThreadContext.bind(subject);
	        return subject;
		}
		return super.getSubject(request, response);
	}
	
	protected boolean onAccessSuccess(Object mappedValue, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {
		if (!CollectionUtils.isEmpty(successHandlers)) {
			for (AuthorizationSuccessHandler successHandler : successHandlers) {
				if (successHandler != null && successHandler.supports(this)) {
					return successHandler.onAuthorizationSuccess(mappedValue, subject, request, response); 
				}
			}
		}
		return true;
	}

	protected boolean onAccessFailure(Object mappedValue, AuthenticationException e, ServletRequest request,
			ServletResponse response) throws IOException {
		
		if (LOG.isDebugEnabled()) {
        	LOG.debug( "Authorization exception", e );
        }
			
		if (!CollectionUtils.isEmpty(failureHandlers)) {
			for (AuthorizationFailureHandler failureHandler : failureHandlers) {
				if (failureHandler != null && failureHandler.supports(e)) {
					return failureHandler.onAuthorizationFailure(mappedValue, e, request, response);
				}
			}
		}
		
		return false;
	}
	
	protected String getHost(ServletRequest request) {
		return WebUtils.getRemoteAddr(request);
	}

	public boolean isSessionStateless() {
		return sessionStateless;
	}

	public void setSessionStateless(boolean sessionStateless) {
		this.sessionStateless = sessionStateless;
	}

	public List<AuthorizationSuccessHandler> getSuccessHandlers() {
		return successHandlers;
	}

	public void setSuccessHandlers(List<AuthorizationSuccessHandler> successHandlers) {
		this.successHandlers = successHandlers;
	}

	public List<AuthorizationFailureHandler> getFailureHandlers() {
		return failureHandlers;
	}

	public void setFailureHandlers(List<AuthorizationFailureHandler> failureHandlers) {
		this.failureHandlers = failureHandlers;
	}

}
