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
package org.apache.shiro.biz.web.filter;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.filter.PathMatchingFilter;
import org.apache.shiro.web.util.WebUtils;

/**
 * 
 * @className	： FormLoginFilter
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年9月12日 下午10:49:07
 * @version 	V1.0
 */
public class FormLoginFilter extends PathMatchingFilter {
	
    private String loginUrl = "/login.jsp";
    private String successUrl = "/";
    
    /*
     *  1、首先判断是否已经登录过了，如果已经登录过了继续拦截器链即可；
	 * 	2、如果没有登录，看看是否是登录请求，如果是get方法的登录页面请求，则继续拦截器链（到请求页面），否则如果是get方法的其他页面请求则保存当前请求并重定向到登录页面；
	 * 	3、如果是post方法的登录页面表单提交请求，则收集用户名/密码登录即可，如果失败了保存错误消息到“shiroLoginFailure”并返回到登录页面；
	 * 	4、如果登录成功了，且之前有保存的请求，则重定向到之前的这个请求，否则到默认的成功页面。
     */
    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        if(SecurityUtils.getSubject().isAuthenticated()) {
        	//已经登录过
            return true;
        }
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        if(isLoginRequest(req)) {
            if("post".equalsIgnoreCase(req.getMethod())) {//form表单提交
                boolean loginSuccess = login(req); //登录
                if(loginSuccess) {
                    return redirectToSuccessUrl(req, resp);
                }
            }
            return true;//继续过滤器链
        } else {//保存当前地址并重定向到登录界面
            saveRequestAndRedirectToLogin(req, resp);
            return false;
        }
    }
    
    private boolean redirectToSuccessUrl(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        WebUtils.redirectToSavedRequest(req, resp, successUrl);
        return false;
    }
    
    private void saveRequestAndRedirectToLogin(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        WebUtils.saveRequest(req);
        WebUtils.issueRedirect(req, resp, loginUrl);
    }

    private boolean login(HttpServletRequest req) {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        try {
            SecurityUtils.getSubject().login(new UsernamePasswordToken(username, password));
        } catch (Exception e) {
            req.setAttribute("shiroLoginFailure", e.getClass());
            return false;
        }
        return true;
    }
    
    private boolean isLoginRequest(HttpServletRequest req) {
        return pathsMatch(loginUrl, WebUtils.getPathWithinApplication(req));
    }
    
}