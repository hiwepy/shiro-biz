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
 * 用户状态异常
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class InvalidStateException extends AccountException{

	/**
	 * 
	 */
	private static final long serialVersionUID = 7850089047311189478L;

	public InvalidStateException() {
		super();

	}

	public InvalidStateException(String message, Throwable cause) {
		super(message, cause);

	}

	public InvalidStateException(String message) {
		super(message);

	}

	public InvalidStateException(Throwable cause) {
		super(cause);

	}

}
