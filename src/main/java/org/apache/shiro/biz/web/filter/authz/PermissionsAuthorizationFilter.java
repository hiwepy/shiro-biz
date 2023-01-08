package org.apache.shiro.biz.web.filter.authz;

import org.apache.shiro.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * 
 * TODO
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 * @see org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter
 */
public class PermissionsAuthorizationFilter extends AbstracAuthorizationFilter {

	protected boolean checkPerms(Subject subject, Object mappedValue){
        String[] perms = (String[]) mappedValue;
        boolean isPermitted = true;
        if (perms != null && perms.length > 0) {
            if (perms.length == 1) {
                if (!subject.isPermitted(perms[0])) {
                    isPermitted = false;
                }
            } else {
                if (!subject.isPermittedAll(perms)) {
                    isPermitted = false;
                }
            }
        }
        return isPermitted;
	}
	
	@Override
	public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {
        Subject subject = getSubject(request, response);
        return checkPerms(subject, mappedValue);
    }

}