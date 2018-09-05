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

import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;

public class StatelessDefaultSubjectFactory extends DefaultWebSubjectFactory {

	private final DefaultSessionStorageEvaluator storageEvaluator;
	/**
	 * If Session Stateless
	 */
	private final boolean stateless;

	/**
	 * DefaultSessionStorageEvaluator是否持久化SESSION的开关
	 */
	public StatelessDefaultSubjectFactory(DefaultSessionStorageEvaluator storageEvaluator, boolean stateless) {
		this.storageEvaluator = storageEvaluator;
		this.stateless = stateless;
	}

	public Subject createSubject(SubjectContext context) {
		storageEvaluator.setSessionStorageEnabled(Boolean.TRUE);
		context.setSessionCreationEnabled(true);
		if (stateless) {
			// 不创建 session
			context.setSessionCreationEnabled(Boolean.FALSE);
			// 不持久化session
			storageEvaluator.setSessionStorageEnabled(Boolean.FALSE);
		}
		return super.createSubject(context);
	}

	public DefaultSessionStorageEvaluator getStorageEvaluator() {
		return storageEvaluator;
	}

	public boolean isStateless() {
		return stateless;
	}
	
}