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
package org.apache.shiro.biz.authc.exception;

import org.apache.shiro.authc.AccountException;

/**
 * 
 * @className	： InvalidAccountException
 * @description	： 无效账号异常
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年8月26日 下午6:07:47
 * @version 	V1.0
 */
public class InvalidAccountException extends AccountException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2110512266031697524L;

	public InvalidAccountException() {
		super();
	}

	public InvalidAccountException(String message, Throwable cause) {
		super(message, cause);
	}

	public InvalidAccountException(String message) {
		super(message);
	}

	public InvalidAccountException(Throwable cause) {
		super(cause);
	}

	
}
