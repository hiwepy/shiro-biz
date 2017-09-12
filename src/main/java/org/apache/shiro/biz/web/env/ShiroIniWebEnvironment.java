/*
 * Copyright (c) 2010-2020, vindell (https://github.com/vindell).
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
package org.apache.shiro.biz.web.env;

import javax.servlet.Filter;

import org.apache.shiro.util.ClassUtils;
import org.apache.shiro.web.env.IniWebEnvironment;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.filter.authz.RolesAuthorizationFilter;
import org.apache.shiro.web.filter.mgt.DefaultFilter;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;

/**
 * 
 * @className	： ShiroIniWebEnvironment
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年9月12日 下午10:49:02
 * @version 	V1.0
 */
public class ShiroIniWebEnvironment extends IniWebEnvironment {

	@Override
    protected FilterChainResolver createFilterChainResolver() {  
        //在此处扩展自己的FilterChainResolver  
        //return super.createFilterChainResolver();  
        
		//1、创建FilterChainResolver  
        PathMatchingFilterChainResolver filterChainResolver =  new PathMatchingFilterChainResolver();  
        //2、创建FilterChainManager  
        DefaultFilterChainManager filterChainManager = new DefaultFilterChainManager();  
        //3、注册Filter  
        for(DefaultFilter filter : DefaultFilter.values()) {  
            filterChainManager.addFilter( filter.name(), (Filter) ClassUtils.newInstance(filter.getFilterClass()));  
        }  
        //4、注册URL-Filter的映射关系  
        filterChainManager.addToChain("/login.jsp", "authc");  
        filterChainManager.addToChain("/unauthorized.jsp", "anon");  
        filterChainManager.addToChain("/**", "authc");  
        filterChainManager.addToChain("/**", "roles", "admin");  
          
        //5、设置Filter的属性  
        FormAuthenticationFilter authcFilter =  
                 (FormAuthenticationFilter)filterChainManager.getFilter("authc");  
        authcFilter.setLoginUrl("/login.jsp");  
        RolesAuthorizationFilter rolesFilter =  
                  (RolesAuthorizationFilter)filterChainManager.getFilter("roles");  
        rolesFilter.setUnauthorizedUrl("/unauthorized.jsp");  
          
        filterChainResolver.setFilterChainManager(filterChainManager);  
        return filterChainResolver;   
        
    }
	
}
