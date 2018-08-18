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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

public class ShiroAnyRolesAuthorizationFilter extends AuthorizationFilter {

	 /*
     * 1、首先判断用户有没有任意角色，如果没有返回false，将到onAccessDenied进行处理；
	 * 2、如果用户没有角色，接着判断用户有没有登录，如果没有登录先重定向到登录；
	 * 3、如果用户没有角色且设置了未授权页面（unauthorizedUrl），那么重定向到未授权页面；否则直接返回401未授权错误码。
     */
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        String[] roles = (String[])mappedValue;
        if(roles == null) {
            return true;//如果没有设置角色参数，默认成功
        }
        for(String role : roles) {
            if(getSubject(request, response).hasRole(role)) {
                return true;
            }
        }
        return false;//跳到onAccessDenied处理
    }
    
    @Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
		
		Subject subject = getSubject(request, response);
        //未认证
        if (null == subject.getPrincipal()) {
    		if (WebUtils.isAjaxRequest(request)) {
    	        WebUtils.writeJSONString(response, HttpServletResponse.SC_UNAUTHORIZED, "Unauthentication.");
    	        return false;
    		}
            saveRequestAndRedirectToLogin(request, response);
        //未授权
        } else {
        	if (WebUtils.isAjaxRequest(request)) {
    	        WebUtils.writeJSONString(response, HttpServletResponse.SC_FORBIDDEN, "Forbidden.");
    	        return false;
    		}else{
    			 // If subject is known but not authorized, redirect to the unauthorized URL if there is one
                // If no unauthorized URL is specified, just return an unauthorized HTTP status code
                String unauthorizedUrl = getUnauthorizedUrl();
                //SHIRO-142 - ensure that redirect _or_ error code occurs - both cannot happen due to response commit:
                if (StringUtils.hasText(unauthorizedUrl)) {
                    WebUtils.issueRedirect(request, response, unauthorizedUrl);
                } else {
                    WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
                }
    		}
        }
        return false;
	}

}
