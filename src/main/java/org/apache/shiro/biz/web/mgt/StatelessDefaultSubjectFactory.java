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
package org.apache.shiro.biz.web.mgt;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.apache.shiro.web.subject.WebSubjectContext;
import org.apache.shiro.web.subject.support.WebDelegatingSubject;

public class StatelessDefaultSubjectFactory extends DefaultWebSubjectFactory {

	/**
	 * If Session Stateless
	 */
	private final boolean sessionStateless;

	/**
	 * DefaultSessionStorageEvaluator是否持久化SESSION的开关
	 */
	public StatelessDefaultSubjectFactory(boolean sessionStateless) {
		this.sessionStateless = sessionStateless;
	}

	public Subject createSubject(SubjectContext context) {
		
		if (sessionStateless) {
			// 不创建 session
			context.setSessionCreationEnabled(Boolean.FALSE);
		}
		
		if (!(context instanceof WebSubjectContext)) {
            return super.createSubject(context);
        }
		
        WebSubjectContext wsc = (WebSubjectContext) context;
        SecurityManager securityManager = wsc.resolveSecurityManager();
        Session session = wsc.resolveSession();
        boolean sessionEnabled = wsc.isSessionCreationEnabled();
        
        PrincipalCollection principals = wsc.resolvePrincipals();
        boolean authenticated =  sessionStateless ? false : wsc.resolveAuthenticated();
        String host = wsc.resolveHost();
        ServletRequest request = wsc.resolveServletRequest();
        ServletResponse response = wsc.resolveServletResponse();
        
        return new WebDelegatingSubject(principals, authenticated, host, session, sessionEnabled,
                request, response, securityManager);
        
	}

	public boolean isSessionStateless() {
		return sessionStateless;
	}
	
}