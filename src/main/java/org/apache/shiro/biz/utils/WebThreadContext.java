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

import java.util.Locale;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.shiro.util.ThreadContext;

public class WebThreadContext extends ThreadContext {

    /**
     * Constant for the HTTP request object.
     */
    public static final String HTTP_REQUEST = "javax.servlet.http.HttpServletRequest";
    /**
     * Constant for the HTTP response object.
     */
    public static final String HTTP_RESPONSE = "javax.servlet.http.HttpServletResponse";
    /**
     * Constant for the HTTP locale object.
     */
    public static final String HTTP_LOCALE = "java.util.Locale";
    /**
     * Constant for the {@link javax.servlet.ServletContext servlet context} object.
     */
    public static final String SERVLET_CONTEXT = "javax.servlet.ServletContext";
    
	/**
	 * 绑定ServletContext对象到当前上下文
	 * @param servletContext {@link ServletContext} 对象
	 */
	public static void bindServletContext(ServletContext servletContext){
		if (servletContext != null) {
			put(SERVLET_CONTEXT, servletContext);
		}
	}
	
	/**
	 * 绑定ServletRequest对象到当前上下文
	 * @param request {@link ServletRequest} 对象
	 */
	public static void bindRequest(ServletRequest request){
		if (request != null) {
			put(HTTP_REQUEST, request);
		}
	}
	
	/**
	 * 绑定ServletResponse对象到当前上下文
	 * @param response {@link ServletResponse} 对象
	 */
	public static void bindResponse(ServletResponse response){
		if (response != null) {
			put(HTTP_RESPONSE, response);
		}
	}
	
	
	/**
	 * 获取ServletRequest
	 * @return {@link ServletRequest} 对象
	 */
	public static ServletRequest getRequest(){
		return (ServletRequest) get(HTTP_REQUEST);
	}
	
	/**
	 * 获取HttpSession
	 * @return {@link HttpSession} 对象
	 */
	public static HttpSession getSession() {
		HttpServletRequest request = (HttpServletRequest) getRequest();
		return request.getSession();
	}
	
	/**
	 * 获取ServletResponse
	 * @return {@link ServletResponse} 对象
	 */
	public static ServletResponse getResponse(){
		return (ServletResponse) get(HTTP_RESPONSE);
	}
	
	/**
	 * 获取ServletContext
	 * @return {@link ServletContext} 对象
	 */
	public static ServletContext getServletContext(){
		return (ServletContext) get(SERVLET_CONTEXT);
	}
	
	/**
	 * 绑定键值对到到当前上下文的ServletContext对象中
	 * @param name 属性名
	 * @param object 属性值
	 */
	public static void setAttribute(String name, Object object){
		ServletContext servletContext = getServletContext();
		if( servletContext != null){
			servletContext.setAttribute(name, object);
		}
	}
	
	/**
	 * 
	 * 获取ServletContext对象中的属性对象
	 * @param name 属性名称
	 * @return ServletContext对象中的属性对象
	 */
	public static Object getAttribute(String name){
		ServletContext servletContext = getServletContext();
		if( servletContext != null){
			return servletContext.getAttribute(name);
		}
		return null;
	}
	
	@SuppressWarnings("unchecked")
	public static <T> T getAttribute(String name,Class<T> targetClass){
		ServletContext servletContext = getServletContext();
		if( servletContext != null){
			return (T) servletContext.getAttribute(name);
		}
		return null;
	}
	
    /**
     * Sets the Locale for the current action.
     *
     * @param locale the Locale for the current action.
     */
    public static void setLocale(Locale locale) {
        put(HTTP_LOCALE, locale);
    }

    /**
     * Gets the Locale of the current action. If no locale was ever specified the platform's
     * {@link java.util.Locale#getDefault() default locale} is used.
     * @return the Locale of the current action.
     */
    public static Locale getLocale() {
        Locale locale = (Locale) get(HTTP_LOCALE);

        if (locale == null) {
            locale = Locale.getDefault();
            setLocale(locale);
        }

        return locale;
    }
    
}
