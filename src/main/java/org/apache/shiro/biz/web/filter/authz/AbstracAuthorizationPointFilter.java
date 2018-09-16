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

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.authc.exception.AuthzPluginNotFoundException;
import org.apache.shiro.biz.authc.exception.AuthzPointNotFoundException;
import org.apache.shiro.biz.pf4j.annotation.AuthzMapping;
import org.apache.shiro.biz.pf4j.point.AuthorizationExtensionPoint;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;
import org.pf4j.ExtensionPoint;
import org.pf4j.PluginManager;
import org.pf4j.PluginWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 基于Pf4插件的抽象的授权 (authorization)过滤器
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public abstract class AbstracAuthorizationPointFilter extends AuthorizationFilter  {

	private static final Logger LOG = LoggerFactory.getLogger(AbstracAuthorizationPointFilter.class);
	private ThreadLocal<AuthorizationExtensionPoint> THREAD_LOCAL = new ThreadLocal<AuthorizationExtensionPoint>();
	private PluginManager pluginManager;
	
	@Override
	protected boolean isEnabled(ServletRequest request, ServletResponse response) throws ServletException, IOException {
		return getAuthzPoint(request, response).isEnabled(request, response);
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		return getAuthzPoint(request, response).isAccessAllowed(request, response, mappedValue);
	}

	@Override
	protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
		return getAuthzPoint(request, response).isLoginRequest(request, response);
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		AuthorizationExtensionPoint authzPoint = getAuthzPoint(request, response);
		if(authzPoint.isPointSubmission(request, response)) {
			return authzPoint.onAccessDenied(request, response, mappedValue);	
		}
		return super.onAccessDenied(request, response, mappedValue);
	}
	
	protected AuthorizationExtensionPoint getAuthzPoint(ServletRequest request, ServletResponse response) {
		AuthorizationExtensionPoint authzPoint = THREAD_LOCAL.get();
		if(authzPoint == null) {
			String pluginId =  this.getPluginId(request, response);
			// 检查插件是否加载
			PluginWrapper wrapper = getPluginManager().getPlugin(pluginId);
			if(wrapper == null) {
				throw new AuthzPluginNotFoundException(String.format("Pf4j plugin not found whith pluginId [%s]", pluginId));
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
						&& extension instanceof AuthorizationExtensionPoint) {
					authzPoint = (AuthorizationExtensionPoint) extension;
					THREAD_LOCAL.set(authzPoint);
					break;
				}
			}
			if(authzPoint == null) {
				throw new AuthzPointNotFoundException(String.format("Authz Extension Point not found whith pluginId [%s], extensionId [%s]", pluginId, extensionId));
			}
		}
		return authzPoint;
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
