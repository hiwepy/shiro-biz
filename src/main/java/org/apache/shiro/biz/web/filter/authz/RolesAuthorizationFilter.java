/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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
package org.apache.shiro.biz.web.filter.authz;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.Set;

/**
 * 
 * TODO
 * 
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 * @see org.apache.shiro.web.filter.authz.RolesAuthorizationFilter
 */
public class RolesAuthorizationFilter extends AbstracAuthorizationFilter {

	protected boolean checkRoles(Subject subject, Object mappedValue) {

		String[] rolesArray = (String[]) mappedValue;
		if (rolesArray == null || rolesArray.length == 0) {
			// no roles specified, so nothing to check - allow access.
			return true;
		}

		Set<String> roles = CollectionUtils.asSet(rolesArray);
		return subject.hasAllRoles(roles);

	}
	
	@Override
	public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws IOException {

		Subject subject = getSubject(request, response);

		return checkRoles(subject, mappedValue);
	}

}
