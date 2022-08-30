<!DOCTYPE html>
<%--
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
--%>
<%@ page language="java" pageEncoding="utf-8" contentType="text/html;charset=utf-8" errorPage="/error.jsp"%>
<%@ page import="org.unitime.timetable.ApplicationProperties" %>
<%@page import="org.cpsolver.ifs.util.JProf"%>
<%@page import="java.text.NumberFormat"%>
<%@ taglib uri="http://www.unitime.org/tags-custom" prefix="tt" %>
<%@ taglib uri="http://struts.apache.org/tags-logic" prefix="logic" %>
<%@ taglib uri="http://java.sun.com/jstl/core_rt" prefix="c" %>
<%@ taglib uri="http://www.unitime.org/tags-localization" prefix="loc" %>

<HTML>
	<HEAD>
	    <meta charset="UTF-8"/>
	    <meta http-equiv="X-UA-Compatible" content="IE=Edge">
 	   <link type="text/css" rel="stylesheet" href="unitime/gwt/standard/standard.css">
 	   <link type="text/css" rel="stylesheet" href="styles/unitime.css">
 	   <link type="text/css" rel="stylesheet" href="styles/unitime-mobile.css">
 	   <link type="text/css" rel="stylesheet" href="styles/timetabling.css">
 	   <loc:rtl><link type="text/css" rel="stylesheet" href="styles/unitime-rtl.css"></loc:rtl>
		<link rel="shortcut icon" href="images/timetabling.ico" />
	    <script type="text/javascript" language="javascript" src="unitime/unitime.nocache.js"></script>
		<TITLE>UniTime <%=Constants.VERSION%></TITLE>
	</HEAD>
	<BODY class="bodyMain" onload="document.forms[0].username.focus();">
	
	<% if (ApplicationProperties.getProperty("tmtbl.header.external", "").trim().length()>0) { %>
	<jsp:include flush="true" page='<%=ApplicationProperties.getProperty("tmtbl.header.external")%>' />
	<% } %>
	
	<span class='top-menu'>
    	<span id='UniTimeGWT:TopMenu' style="display: block; height: 23px;"></span>
    </span>

	<tt:hasProperty name="tmtbl.global.info">
    	<div class='unitime-PageMessage'><tt:property name="tmtbl.global.info"/></div>
	</tt:hasProperty>
	<tt:hasProperty name="tmtbl.global.warn">
    	<div class='unitime-PageWarn'><tt:property name="tmtbl.global.warn"/></div>
	</tt:hasProperty>
	<tt:hasProperty name="tmtbl.global.error">
    	<div class='unitime-PageError'><tt:property name="tmtbl.global.error"/></div>
	</tt:hasProperty>
	<tt:page-warning prefix="tmtbl.page.warn." style="unitime-PageWarn" page="login"/>
	<tt:page-warning prefix="tmtbl.page.info." style="unitime-PageMessage" page="login"/>
	<tt:page-warning prefix="tmtbl.page.error." style="unitime-PageError" page="login"/>
	
<%
	String errorMsg = null;
	if (request.getParameter("e")!=null) {
		String eNum = request.getParameter("e");
		if (eNum.equals("1"))
			errorMsg = "Invalid username/password";
		if (eNum.equals("2"))
			errorMsg = "Authentication failed";
		if (eNum.equals("3"))
			errorMsg = "Authentication failed";
		if (eNum.equals("4"))
			errorMsg = "User temporarily locked out -<br> Exceeded maximum failed login attempts.";
	} else if (request.getParameter("m")!=null) {
		errorMsg = (String)request.getParameter("m");
	}
 %>		

<FORM name="f" action="<c:url value='login'/>" method="POST">
	<INPUT type="hidden" name="cs" value="login">
	<INPUT type="hidden" name="menu" value="<%=request.getParameter("menu") == null ? "" : request.getParameter("menu") %>">
	<INPUT type="hidden" name="target" value="<%=request.getParameter("target") == null ? "" : request.getParameter("target") %>">
	<INPUT type="hidden" name="oauthCode" value="<%=request.getParameter("code") == null ? "" : request.getParameter("code") %>">
			
	<span class='unitime-Login'>
		<span class="mobile-menu-button" id='UniTimeGWT:MobileMenuButton'></span>
		<span class='logo'><img src="images/unitime.png" border="0" alt="UniTime"></span>
		<span class='header'>
			<div class='h1'>University Timetabling</div>
			<div class='h2'>Comprehensive Academic Scheduling Solutions</div>
		</span>
		<span class="mobile-menu" id='UniTimeGWT:MobileMenuPanel'></span>
		<% if (errorMsg!=null)  { %><div class='error'><%= errorMsg %></div><% } %>
		<c:if test="${not empty SPRING_SECURITY_LAST_EXCEPTION.message}">
			<div class='error'>Authentication failed: <c:out value="${SPRING_SECURITY_LAST_EXCEPTION.message}"/>.</div>
		</c:if>
		<span class='login'>
			<div id="login">
				<div class="BrownBG">
					<div class="H40px"></div>
					<div><label>Username:</label></div>
					<div class="txtField"><input type='text' name='username' value='<c:if test="${not empty SPRING_SECURITY_LAST_USERNAME}"><c:out value="${SPRING_SECURITY_LAST_USERNAME}"/></c:if>' aria-label='Enter user name'/></div>
					<div class="H20px"></div>
					<div><label>Password:</label></div>
					<div class="txtField"><input type='password' name='password' aria-label='Enter password'></div>
				</div>
				<div class="bottom"><img src="images/login_bg_2.jpg"/><input id="submit" name="submit" type="image" src="images/login_bg_3.jpg" border="0" align="top" value="log in" alt="Submit login information."><img src="images/login_bg_4.jpg"/></div>
			</div>
		</span>
		<c:if test="${SUGGEST_PASSWORD_RESET}">
			<span class='forgot'><a href='gwt.jsp?page=password&reset=1' class='unitime-FooterLink'>Forgot your password?</a></span>
		</c:if>
	</span>
</FORM>
		
		<%@ include file="/initializationError.jspf"%>
		
		<span class="unitime-Footer">
			<span class="row">
				<span class="cell middle">
					<span id='UniTimeGWT:Version'></span>
					<tt:copy br="false"/>
				</span>
			</span>
		</span>
		<tt:hasProperty name="tmtbl.page.disclaimer">
			<span class='unitime-Disclaimer'><tt:property name="tmtbl.page.disclaimer"/></span>
		</tt:hasProperty>
		

		<% if (ApplicationProperties.getProperty("tmtbl.footer.external", "").trim().length()>0) { %>
			<jsp:include flush="true" page='<%=ApplicationProperties.getProperty("tmtbl.footer.external")%>' />
		<% } %>

		<style>
			.wwu-button {
				display: flex;
				justify-content: center;
				align-items: center;
				height: 100px;	
			}
		</style>

		<div class="wwu-button">
			<button onclick="loginWithWWU()">Login with WWU</button>
		</div>

		<div class="wwu-button">
			<button onclick="loginAsTrevor()">Login as Trevor</button>
		</div>


		<script>
			function loginWithWWU() {
				window.open("https://login.microsoftonline.com/d958f048-e431-4277-9c8d-ebfb75e7aa64/oauth2/v2.0/authorize?client_id=98ae7ee1-eb75-4a49-a7c0-c7074eb64e02&redirect_uri=https://unitime-ssotest.wallawalla.edu/UniTime/selectPrimaryRole.do&scope=openid&response_type=code&response_mode=fragment&nonce=dslkdjfsi", "_self")
			}
		</script>

		<script>
			function loginAsTrevor() {
				document.getElementsByName("username")[0].setAttribute("value", "trevor");
				document.getElementsByName("password")[0].setAttribute("value", "unitimetrev");
				document.getElementsByName("f")[0].submit();
			}
		</script>

	<script>
		window.onload = function() {
			const url = window.location.href;
			console.log(url);
			if (url.includes("#code=")) {
				const code = url.slice(url.indexOf("=") + 1, url.indexOf("&"));
				console.log("Authorization code = ", code);
				document.getElementsByName("username")[0].setAttribute("value", "OAuth2");
				document.getElementsByName("password")[0].setAttribute("value", code);
				document.getElementsByName("f")[0].submit();
			}
		}
	</script>
</HTML>
