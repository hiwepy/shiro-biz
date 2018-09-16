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
package org.apache.shiro.biz.utils;

import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.biz.authc.exception.AuthcPluginNotFoundException;
import org.apache.shiro.biz.authc.exception.AuthcPointNotFoundException;
import org.apache.shiro.biz.authc.exception.AuthzPluginNotFoundException;
import org.apache.shiro.biz.authc.exception.AuthzPointNotFoundException;
import org.apache.shiro.biz.pf4j.annotation.AuthzMapping;
import org.apache.shiro.biz.pf4j.point.AuthenticatingExtensionPoint;
import org.apache.shiro.biz.pf4j.point.AuthorizationExtensionPoint;
import org.pf4j.ExtensionPoint;
import org.pf4j.PluginManager;
import org.pf4j.PluginWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PluginPointUtils {
	
	private static final Logger LOG = LoggerFactory.getLogger(PluginPointUtils.class);
	public static ThreadLocal<AuthenticatingExtensionPoint> AUTHC_THREAD_LOCAL = new ThreadLocal<AuthenticatingExtensionPoint>();
	public static ThreadLocal<AuthorizationExtensionPoint> AUTHZ_THREAD_LOCAL = new ThreadLocal<AuthorizationExtensionPoint>();
	
	public static AuthenticatingExtensionPoint getAuthcPoint(ServletRequest request, ServletResponse response, 
			PluginManager pluginManager, String pluginId, String extensionId) throws AuthenticationException {
		AuthenticatingExtensionPoint authcPoint = AUTHC_THREAD_LOCAL.get();
		if(authcPoint == null) {
			// 检查插件是否加载
			PluginWrapper wrapper = pluginManager.getPlugin(pluginId);
			if(wrapper == null) {
				throw new AuthcPluginNotFoundException(String.format("Pf4j plugin not found whith pluginId [%s]", pluginId));
			}
			// 记录日志
			if(LOG.isDebugEnabled()) {
				LOG.debug(wrapper.toString());
			}
			// 查找插件内的实现对象
			List<ExtensionPoint> extensions = pluginManager.getExtensions(ExtensionPoint.class, pluginId);
			for (ExtensionPoint extension : extensions) {
				// 注解信息
				AuthzMapping mapping = extension.getClass().getAnnotation(AuthzMapping.class);
				// 判断类型
				if(mapping != null && StringUtils.equals(mapping.id(), extensionId) 
						&& extension instanceof AuthenticatingExtensionPoint) {
					authcPoint = (AuthenticatingExtensionPoint) extension;
					AUTHC_THREAD_LOCAL.set(authcPoint);
					break;
				}
			}
			if(authcPoint == null) {
				throw new AuthcPointNotFoundException(String.format("Authc Extension Point not found whith pluginId [%s], extensionId [%s]", pluginId, extensionId));
			}
		}
		return authcPoint;
	}
	
	public static AuthorizationExtensionPoint getAuthzPoint(ServletRequest request, ServletResponse response, 
			PluginManager pluginManager, String pluginId, String extensionId) throws AuthenticationException {
		AuthorizationExtensionPoint authzPoint = AUTHZ_THREAD_LOCAL.get();
		if(authzPoint == null) {
			// 检查插件是否加载
			PluginWrapper wrapper = pluginManager.getPlugin(pluginId);
			if(wrapper == null) {
				throw new AuthzPluginNotFoundException(String.format("Pf4j plugin not found whith pluginId [%s]", pluginId));
			}
			// 记录日志
			if(LOG.isDebugEnabled()) {
				LOG.debug(wrapper.toString());
			}
			// 查找插件内的实现对象
			List<ExtensionPoint> extensions = pluginManager.getExtensions(ExtensionPoint.class, pluginId);
			for (ExtensionPoint extension : extensions) {
				// 注解信息
				AuthzMapping mapping = extension.getClass().getAnnotation(AuthzMapping.class);
				// 判断类型
				if(mapping != null && StringUtils.equals(mapping.id(), extensionId) 
						&& extension instanceof AuthorizationExtensionPoint) {
					authzPoint = (AuthorizationExtensionPoint) extension;
					AUTHZ_THREAD_LOCAL.set(authzPoint);
					break;
				}
			}
			if(authzPoint == null) {
				throw new AuthzPointNotFoundException(String.format("Authz Extension Point not found whith pluginId [%s], extensionId [%s]", pluginId, extensionId));
			}
		}
		return authzPoint;
	}

}
