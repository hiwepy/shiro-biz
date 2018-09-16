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
package org.apache.shiro.biz.web.filter.authc;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.exception.AuthcPluginNotFoundException;
import org.apache.shiro.biz.authc.exception.AuthcPointNotFoundException;
import org.apache.shiro.biz.pf4j.annotation.AuthzMapping;
import org.apache.shiro.biz.pf4j.point.AuthenticatingExtensionPoint;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.web.filter.authz.AbstracAuthorizationPointFilter;
import org.apache.shiro.subject.Subject;
import org.pf4j.ExtensionPoint;
import org.pf4j.PluginManager;
import org.pf4j.PluginWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 基于Pf4插件的抽象的认证 (authentication)过滤器
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public abstract class AbstractAuthenticatingPointFilter extends AbstractAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(AbstracAuthorizationPointFilter.class);
	private ThreadLocal<AuthenticatingExtensionPoint> THREAD_LOCAL = new ThreadLocal<AuthenticatingExtensionPoint>();
	private PluginManager pluginManager;
	
	@Override
	protected boolean isEnabled(ServletRequest request, ServletResponse response) throws ServletException, IOException {
		return getAuthcPoint(request, response).isEnabled(request, response);
	}
	
	@Override
	protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
		return getAuthcPoint(request, response).isLoginRequest(request, response);
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		return getAuthcPoint(request, response).isAccessAllowed(request, response, mappedValue);
	}
	
	@Override
	protected boolean isLoginSubmission(ServletRequest request, ServletResponse response) {
		return getAuthcPoint(request, response).isLoginSubmission(request, response);
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		if(isLoginSubmission(request, response)) {
			return getAuthcPoint(request, response).onAccessDenied(request, response, mappedValue);	
		}
		return super.onAccessDenied(request, response, mappedValue);
	}
	
	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
		return getAuthcPoint(request, response).createToken(request, response);
	}
	
	@Override
	protected void cleanup(ServletRequest request, ServletResponse response, Exception existing)
			throws ServletException, IOException {
		try {
			getAuthcPoint(request, response).cleanup(request, response, existing);
		} catch (Exception e) {
			super.cleanup(request, response, existing);
		}
	}
	
	@Override
	protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception{
		return getAuthcPoint(request, response).onLoginSuccess(token, subject, request, response);
	}
	
	@Override
	protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request,
			ServletResponse response) {
		return getAuthcPoint(request, response).onLoginFailure(token, e, request, response);
	}
	
	@Override
	protected boolean onAccessSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response) {
		return getAuthcPoint(request, response).onAccessSuccess(token, subject, request, response);
	}
	
	@Override
	protected boolean onAccessFailure(AuthenticationToken token, Exception e, ServletRequest request,
			ServletResponse response) {
		return getAuthcPoint(request, response).onAccessFailure(token, e, request, response);
	}
	
	protected AuthenticatingExtensionPoint getAuthcPoint(ServletRequest request, ServletResponse response) {
		AuthenticatingExtensionPoint authcPoint = THREAD_LOCAL.get();
		if(authcPoint == null) {
			String pluginId =  this.getPluginId(request, response);
			// 检查插件是否加载
			PluginWrapper wrapper = getPluginManager().getPlugin(pluginId);
			if(wrapper == null) {
				throw new AuthcPluginNotFoundException(String.format("Pf4j plugin not found whith pluginId [%s]", pluginId));
			}
			// 记录日志
			if(LOG.isDebugEnabled()) {
				LOG.debug(wrapper.toString());
			}
			// 查找插件内的实现对象
			List<ExtensionPoint> extensions = getPluginManager().getExtensions(ExtensionPoint.class, pluginId);
			String extensionId = this.getExtensionId(request, response);
			for (ExtensionPoint extension : extensions) {
				// 注解信息
				AuthzMapping mapping = extension.getClass().getAnnotation(AuthzMapping.class);
				// 判断类型
				if(mapping != null && StringUtils.equals(mapping.id(), extensionId) 
						&& extension instanceof AuthenticatingExtensionPoint) {
					authcPoint = (AuthenticatingExtensionPoint) extension;
					THREAD_LOCAL.set(authcPoint);
					break;
				}
			}
			if(authcPoint == null) {
				throw new AuthcPointNotFoundException(String.format("Authc Extension Point not found whith pluginId [%s], extensionId [%s]", pluginId, extensionId));
			}
		}
		return authcPoint;
	}

	protected abstract String getPluginId(ServletRequest request, ServletResponse response);
	protected abstract String getExtensionId(ServletRequest request, ServletResponse response);

	public PluginManager getPluginManager() {
		return pluginManager;
	}

	public void setPluginManager(PluginManager pluginManager) {
		this.pluginManager = pluginManager;
	}
	
}