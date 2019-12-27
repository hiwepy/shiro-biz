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
package org.apache.shiro.biz.web.mgt;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;

public class SessionCreationEnabledSubjectFactory extends DefaultWebSubjectFactory {
	
	/**
	 * Whether or not the constructed {@code Subject} instance should be allowed to create a session,
     * {@code false} otherwise.
	 */
	private final boolean sessionCreationEnabled;

	public SessionCreationEnabledSubjectFactory(boolean sessionCreationEnabled) {
		this.sessionCreationEnabled = sessionCreationEnabled;
	}

	public Subject createSubject(SubjectContext context) {
		// 是否创建 session
		context.setSessionCreationEnabled(sessionCreationEnabled);
		return super.createSubject(context);
	}

	public boolean isSessionCreationEnabled() {
		return sessionCreationEnabled;
	}
	
}