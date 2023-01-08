/*
 * Copyright (c) 2018 (https://github.com/hiwepy).
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

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

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
		// 自身类.class.isAssignableFrom(自身类或子类.class) 
		if( clazz.isAssignableFrom(principal.getClass()) ) {
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

	/**
	 * 检查target类型对是否是给出对象类型数组中任意一个的类型的子类或者子接口
	 * @param target
	 * @param classes
	 * @return
	 */
	public static boolean isAssignableFrom(Class<?> target, Class<?> ... classes) {
		if(target != null && classes != null) {
			for (Class<?> clazz : classes) {
				/*
				 *	假设有两个类Class1和Class2。Class1.isAssignableFrom(Class2)表示:
    			 *	1、类Class1和Class2是否相同。
    			 *	2、Class1是否是Class2的父类或接口 
				 */
				// clazz是否和target类型相同或者，clazz是否是target的父类或接口 
				if(clazz != null && clazz.isAssignableFrom(target)) {
					return true;
				};
			}
		}
		return false;
	}
	
	/**
	 * 登陆成功后重新生成session【基于安全考虑】
	 * @param subject {@link Subject} instance
	 * @param oldSession Old {@link Session} instance
	 * @return {@link Session} instance
	 */
	public static Session copySession(Subject subject, Session oldSession) {
		// retain Session attributes to put in the new session after login:
		Map<Object, Object> attributes = new LinkedHashMap<Object, Object>();

		Collection<Object> keys = oldSession.getAttributeKeys();

		for (Object key : keys) {
			Object value = oldSession.getAttribute(key);
			if (value != null) {
				attributes.put(key, value);
			}
		}
		oldSession.stop();
		// restore the attributes:
		Session newSession = subject.getSession();

		for (Object key : attributes.keySet()) {
			newSession.setAttribute(key, attributes.get(key));
		}
		return newSession;
	}

}
