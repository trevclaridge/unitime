/*
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * The Apereo Foundation licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
*/
package org.unitime.timetable.action;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts2.interceptor.ServletResponseAware;
import org.unitime.timetable.form.UniTimeForm;
import org.unitime.timetable.security.SessionContext;
import org.unitime.timetable.security.context.HttpSessionContext;
import org.unitime.timetable.solver.service.SolverServerService;
import org.unitime.timetable.spring.SpringApplicationContextHolder;

import com.opensymphony.xwork2.ActionSupport;

/**
 * Base action for Struts2 actions
 * @author Tomas Muller
 */
public abstract class UniTimeAction<T extends UniTimeForm> extends ActionSupport implements ServletRequestAware, ServletResponseAware {
	private static final long serialVersionUID = 3596810266703379946L;
	protected SessionContext sessionContext;
	protected HttpServletRequest request;
	protected HttpServletResponse response;
	protected T form;
	protected String op;
	
	public T getForm() { return form; }
	public void setForm(T form) { this.form = form; }
	
	public String getOp() { return op; }
	public void setOp(String op) { this.op = op; }
	
	public void setServletRequest(HttpServletRequest request) {
		this.request = request;
		this.sessionContext = new HttpSessionContext(request.getSession());
	}
	
	public void setServletResponse(HttpServletResponse response) {
		this.response = response;
	}
	
	protected SolverServerService getSolverServerService() {
		return (SolverServerService)SpringApplicationContextHolder.getBean("solverServerService");
	}
}
