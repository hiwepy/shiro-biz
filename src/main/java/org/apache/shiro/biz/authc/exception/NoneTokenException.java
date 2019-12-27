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
package org.apache.shiro.biz.authc.exception;

import org.apache.shiro.authc.AccountException;

/**
 * 验证码必须异常
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class NoneTokenException extends AccountException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2110512266031697524L;

	public NoneTokenException() {
		super();
	}

	public NoneTokenException(String message, Throwable cause) {
		super(message, cause);
	}

	public NoneTokenException(String message) {
		super(message);
	}

	public NoneTokenException(Throwable cause) {
		super(cause);
	}

	
}
