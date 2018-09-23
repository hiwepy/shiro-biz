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
package org.apache.shiro.biz.session.mgt;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionFactory;
import org.apache.shiro.session.mgt.SimpleOnlineSession;
import org.apache.shiro.web.session.mgt.WebSessionContext;

/**
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class SimpleOnlineSessionFactory implements SessionFactory {  
	  
    @Override  
    public Session createSession(SessionContext initData) {  
        SimpleOnlineSession session = new SimpleOnlineSession();  
        if (initData != null && initData instanceof WebSessionContext) {  
            WebSessionContext sessionContext = (WebSessionContext) initData;  
            ServletRequest request = sessionContext.getServletRequest();  
            if ( request != null && request instanceof HttpServletRequest) {
                session.setHost(WebUtils.getRemoteAddr(request));  
                session.setUserAgent(WebUtils.toHttp(request).getHeader("User-Agent"));  
                session.setSystemHost(WebUtils.getRemoteAddr(request) + ":" + request.getLocalPort());  
            }  
        }  
        return session;  
    }  
}   