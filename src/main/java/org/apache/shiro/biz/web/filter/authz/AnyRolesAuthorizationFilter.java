/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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

import org.apache.shiro.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class AnyRolesAuthorizationFilter extends AbstracAuthorizationFilter {

	protected boolean checkRoles(Subject subject, Object mappedValue) {

		String[] rolesArray = (String[]) mappedValue;
		if (rolesArray == null || rolesArray.length == 0) {
			// no roles specified, so nothing to check - allow access.
			return true;
		}

		for(String role : rolesArray) {
            if(subject.hasRole(role)) {
                return true;
            }
        }
		 
		 return false;

	}
	
	 /*
     * 1、首先判断用户有没有任意角色，如果没有返回false，将到onAccessDenied进行处理；
	 * 2、如果用户没有角色，接着判断用户有没有登录，如果没有登录先重定向到登录；
	 * 3、如果用户没有角色且设置了未授权页面（unauthorizedUrl），那么重定向到未授权页面；否则直接返回401未授权错误码。
     */
	@Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
    	Subject subject = getSubject(request, response);
        return checkRoles(subject, mappedValue);
    }
    
   

}
