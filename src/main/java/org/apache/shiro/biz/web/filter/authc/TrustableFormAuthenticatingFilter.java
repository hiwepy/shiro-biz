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
package org.apache.shiro.biz.web.filter.authc;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class TrustableFormAuthenticatingFilter extends AbstractTrustableAuthenticatingFilter {

	/**
	 * Whether to redirect to the previous access address
	 */
	private boolean redirectToSavedRequest;
	
	public TrustableFormAuthenticatingFilter() {
		super();
	}
	
	@Override
	protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {
		
		if(isRedirectToSavedRequest()) {
			issueSuccessRedirect(request, response);
		} else {
			WebUtils.issueRedirect(request, response, getSuccessUrl());
		}
		
		// we handled the success redirect directly, prevent the chain from continuing:
        return false;
	}

	public boolean isRedirectToSavedRequest() {
		return redirectToSavedRequest;
	}

	public void setRedirectToSavedRequest(boolean redirectToSavedRequest) {
		this.redirectToSavedRequest = redirectToSavedRequest;
	}
	
}
