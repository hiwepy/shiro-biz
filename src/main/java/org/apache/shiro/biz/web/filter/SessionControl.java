package org.apache.shiro.biz.web.filter;

import java.io.Serializable;

import org.apache.shiro.session.Session;

@SuppressWarnings("serial")
public class SessionControl implements Serializable {

	public static final Serializable STATE_VALID = "valid";

	public static final Serializable STATE_INVALID = "invalid";

	private Serializable sessionid;

	private Session session;

	private Serializable state;

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SessionControl other = (SessionControl) obj;
		if (sessionid == null) {
			if (other.sessionid != null) {
				return false;
			}
		} else if (!sessionid.equals(other.sessionid)) {
			return false;
		}
		return true;
	}

	public Serializable getSessionid() {
		return sessionid;
	}

	public void setSessionid(Serializable sessionid) {
		this.sessionid = sessionid;
	}

	public Serializable getState() {
		return state;
	}

	public void setState(Serializable state) {
		this.state = state;
	}

	public SessionControl(Serializable sessionid) {
		super();
		this.sessionid = sessionid;
	}

	public SessionControl(Serializable sessionid, Serializable state) {
		super();
		this.sessionid = sessionid;
		this.state = state;
	}

	public SessionControl(Session session, Serializable state) {
		super();
		this.session = session;
		this.state = state;
	}

	public SessionControl(Serializable sessionid, Session session, Serializable state) {
		super();
		this.sessionid = sessionid;
		this.session = session;
		this.state = state;
	}

	public Session getSession() {
		return session;
	}

	public void setSession(Session session) {
		this.session = session;
	}

}
