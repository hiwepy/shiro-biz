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

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GenericsUtils {

	/**
     * 日志.
     */
	protected static Logger LOG = LoggerFactory.getLogger(GenericsUtils.class);

    /**
     * 构造方法.
     */
    protected GenericsUtils() {
    }

	/**
	 * 
	 * @description	： 通过反射,获得定义Class时声明的父类的范型参数的类型.如 public BookManager extends GenricManager&lt;Book&gt;
	 * @param sourceClass The class to introspect
     * @return the first generic declaration, or <code>Object.class</code> if cannot be determined
	 */
	public static  Class getSuperClassGenricType(Class sourceClass) {
		return getSuperClassGenricType(sourceClass, 0);
	}

	/**
	 * 
	 * @description	：通过反射,获得定义Class时声明的父类的范型参数的类型. 如public BookManager extends GenricManager&lt;Book&gt;
	 * @author 		： <a href="https://github.com/vindell">vindell</a>
	 * @date 		：2017年9月12日 下午10:49:43
	 * @param sourceClass  The class to introspect
	 * @param index the Index of the generic ddeclaration,start from 0.
	 * @return the index generic declaration, or <code>Object.class</code> if cannot be determined
	 */
	public static Class getSuperClassGenricType(Class sourceClass, int index){
		Type genType = sourceClass.getGenericSuperclass();
		if (!(genType instanceof ParameterizedType)) {
			LOG.warn(sourceClass.getSimpleName()  + "'s superclass not ParameterizedType");
			return Object.class;
		}
		Type[] params = ((ParameterizedType) genType).getActualTypeArguments();
		if ((index >= params.length) || (index < 0)){
			throw new IndexOutOfBoundsException("Index: " + index + ", Size of Parameterized Type: " + params.length);
		}

        if (!(params[index] instanceof Class)) {
            LOG.warn(sourceClass.getSimpleName() + " not set the actual class on superclass generic parameter");
            return Object.class;
        }
		
		return (Class<?>) params[index];
	}
	
	public static Class getSuperClassGenricType(Class sourceClass,Class superclass){
		return getSuperClassGenricType(sourceClass, superclass, 0);
	}
	
	public static Class getSuperClassGenricType(Class sourceClass,Class superclass, int index){
		Type[] types = sourceClass.getGenericInterfaces();
		ParameterizedType genType = null;
		for (Type type : types) {
			if (type instanceof ParameterizedType && ((ParameterizedType) type).getRawType().equals(superclass)) {
				genType = (ParameterizedType) type;
				break;
			}
		}
		if (genType == null) {
			LOG.warn(sourceClass.getSimpleName()  + "'s superclass not ParameterizedType");
			return Object.class;
		}
		
		Type[] params = genType.getActualTypeArguments();
		if ((index >= params.length) || (index < 0)){
			throw new IndexOutOfBoundsException("Index: " + index + ", Size of Parameterized Type: " + params.length);
		}
	
	    if (!(params[index] instanceof Class)) {
	        LOG.warn(sourceClass.getSimpleName() + " not set the actual class on superclass generic parameter");
	        return Object.class;
	    }
		
		return (Class<?>) params[index];
	}
	
}
