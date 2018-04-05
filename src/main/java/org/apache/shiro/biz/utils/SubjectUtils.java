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
package org.apache.shiro.biz.utils;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.subject.WebSubject;

public class SubjectUtils {
	
	public static Subject getSubject(){
		return SecurityUtils.getSubject();
	}
	
   /**
     * Creates a {@link WebSubject} instance to associate with the incoming request/response pair which will be used
     * throughout the request/response execution.
     * @return the {@code WebSubject} instance to associate with the request/response execution
     */
	public static WebSubject getWebSubject(){
		Subject subject = ThreadContext.getSubject();
        if (subject == null) {
        	subject = new WebSubject.Builder( WebThreadContext.getRequest(), WebThreadContext.getResponse()).buildWebSubject();
            ThreadContext.bind(subject);
        }
		return (WebSubject) subject;
	}
	
	
	@SuppressWarnings("unchecked")
	public static <T> T getPrincipal(Class<T> clazz){
		Object principal = getSubject().getPrincipal();
		if(principal.getClass().isAssignableFrom(clazz) ){
			return (T)principal;
		}
		return null;
	}
	
	public static Object getPrincipal(){
		return getSubject().getPrincipal();
	}
	
	public static boolean isAuthenticated(){
		return getSubject().isAuthenticated();
	}
	
	public static Session getSession(){
		return getSubject().getSession();
	}
	
	public static Session getSession(boolean create){
		return getSubject().getSession(create);
	}

}
