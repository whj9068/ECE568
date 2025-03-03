/*
 * Generated by the Jasper component of Apache Tomcat
 * Version: Apache Tomcat/7.0.59
 * Generated at: 2024-03-15 03:21:34 UTC
 * Note: The last modified time of this file was set to
 *       the last modified time of the source file after
 *       generation to assist with modification tracking.
 */
package org.apache.jsp.WEB_002dINF.pages;

import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;

public final class about_jsp extends org.apache.jasper.runtime.HttpJspBase
    implements org.apache.jasper.runtime.JspSourceDependent {

  private static final javax.servlet.jsp.JspFactory _jspxFactory =
          javax.servlet.jsp.JspFactory.getDefaultFactory();

  private static java.util.Map<java.lang.String,java.lang.Long> _jspx_dependants;

  private javax.el.ExpressionFactory _el_expressionfactory;
  private org.apache.tomcat.InstanceManager _jsp_instancemanager;

  public java.util.Map<java.lang.String,java.lang.Long> getDependants() {
    return _jspx_dependants;
  }

  public void _jspInit() {
    _el_expressionfactory = _jspxFactory.getJspApplicationContext(getServletConfig().getServletContext()).getExpressionFactory();
    _jsp_instancemanager = org.apache.jasper.runtime.InstanceManagerFactory.getInstanceManager(getServletConfig());
  }

  public void _jspDestroy() {
  }

  public void _jspService(final javax.servlet.http.HttpServletRequest request, final javax.servlet.http.HttpServletResponse response)
        throws java.io.IOException, javax.servlet.ServletException {

    final javax.servlet.jsp.PageContext pageContext;
    javax.servlet.http.HttpSession session = null;
    final javax.servlet.ServletContext application;
    final javax.servlet.ServletConfig config;
    javax.servlet.jsp.JspWriter out = null;
    final java.lang.Object page = this;
    javax.servlet.jsp.JspWriter _jspx_out = null;
    javax.servlet.jsp.PageContext _jspx_page_context = null;


    try {
      response.setContentType("text/html; charset=ISO-8859-1");
      pageContext = _jspxFactory.getPageContext(this, request, response,
      			"", true, 8192, true);
      _jspx_page_context = pageContext;
      application = pageContext.getServletContext();
      config = pageContext.getServletConfig();
      session = pageContext.getSession();
      out = pageContext.getOut();
      _jspx_out = out;

      out.write("\n");
      out.write("\n");
      out.write("<!-- This modal content is included into the main_new.jsp -->\n");
      out.write("\n");
      out.write("<div class=\"modal-content\">\n");
      out.write("    <div class=\"modal-header\">\n");
      out.write("        <button type=\"button\" class=\"close\" data-dismiss=\"modal\" aria-hidden=\"true\">&times;</button>\n");
      out.write("        <h3 class=\"modal-title\" id=\"myModalLabel\">About WebGoat - Provided by the OWASP Foundation</h3>\n");
      out.write("    </div>\n");
      out.write("    <div class=\"modal-body modal-scroll\">\n");
      out.write("        <p>Thanks for hacking The Goat!</p> \n");
      out.write("        <p>WebGoat is a demonstration of common web application flaws. The\n");
      out.write("            associated exercises are intended to provide hands-on experience with\n");
      out.write("            techniques aimed at demonstrating and testing application penetration.\n");
      out.write("        </p>\n");
      out.write("        <p>From the entire WebGoat team, we appreciate your interest and efforts\n");
      out.write("            in making applications not just better, but safer and more secure for\n");
      out.write("            everyone. We, as well as our sacrificial goat, thank you.</p>\n");
      out.write("        <p>\n");
      out.write("            Version: ");
      out.write((java.lang.String) org.apache.jasper.runtime.PageContextImpl.proprietaryEvaluate("${version}", java.lang.String.class, (javax.servlet.jsp.PageContext)_jspx_page_context, null, false));
      out.write(",&nbsp;Build: ");
      out.write((java.lang.String) org.apache.jasper.runtime.PageContextImpl.proprietaryEvaluate("${build}", java.lang.String.class, (javax.servlet.jsp.PageContext)_jspx_page_context, null, false));
      out.write("\n");
      out.write("        </p>\n");
      out.write("\n");
      out.write("        <div class=\"row\">\n");
      out.write("            <div class=\"col-md-6\">\n");
      out.write("                <p>Contact us:\n");
      out.write("                <ul>\n");
      out.write("                    <li>WebGoat mailing list: ");
      out.write((java.lang.String) org.apache.jasper.runtime.PageContextImpl.proprietaryEvaluate("${emailList}", java.lang.String.class, (javax.servlet.jsp.PageContext)_jspx_page_context, null, false));
      out.write("</li>\n");
      out.write("                    <li>Bruce Mayhew:  ");
      out.write((java.lang.String) org.apache.jasper.runtime.PageContextImpl.proprietaryEvaluate("${contactEmail}", java.lang.String.class, (javax.servlet.jsp.PageContext)_jspx_page_context, null, false));
      out.write("</li>\n");
      out.write("                </ul>\n");
      out.write("                </p>\n");
      out.write("            </div>\n");
      out.write("        </div>       \n");
      out.write("        <div class=\"row\">\n");
      out.write("            <div class=\"col-md-6\">\n");
      out.write("                <p>WebGoat Authors\n");
      out.write("                <ul>\n");
      out.write("                    <li>Bruce Mayhew   (Author & Project Lead)</li>\n");
      out.write("                    <li>Jeff Williams  (Author & Original Idea)</li>\n");
      out.write("                    <li>Jason White    (Architect)</li>\n");
      out.write("                    <li>Nanne Baars    (Plugin Architecture)</li>\n");
      out.write("                    <li>Richard Lawson (Architect)</li>\n");
      out.write("                </ul>\n");
      out.write("                </p>\n");
      out.write("            </div>\n");
      out.write("            <div class=\"col-md-6\">\n");
      out.write("                <p>Active Contributors\n");
      out.write("                <ul>\n");
      out.write("                    <li>Nanne Baars   (Developer)</li>\n");
      out.write("                    <li>Jason White   (Developer)</li>\n");
      out.write("                    <li>Doug Morato   (Developer & CI)</li>\n");
      out.write("                    <li>Jeff Wayman   (Docs)</li>\n");
      out.write("                    <li>Bruce Mayhew  (Developer)</li>\n");
      out.write("                    <li>Michael Dever (Developer)</li>\n");
      out.write("                </ul>\n");
      out.write("                </p>\n");
      out.write("            </div>\n");
      out.write("        </div>\n");
      out.write("        <div class=\"row\">\n");
      out.write("            <div class=\"col-md-6\">\n");
      out.write("                <p>WebGoat Design Team (Active)\n");
      out.write("                <ul>\n");
      out.write("                    <li>Nanne Baars    (Plugin Architecture)</li>\n");
      out.write("                    <li>Bruce Mayhew   (Goat Herder)</li>\n");
      out.write("                    <li>Jeff Wayman    (Website and Docs)</li>\n");
      out.write("                    <li>Jason White    (User Interface)</li>\n");
      out.write("                </ul>\n");
      out.write("                </p><br></br>\n");
      out.write("                <p>Corporate Sponsorship - Companies that have donated significant time to WebGoat development\n");
      out.write("                <ul>\n");
      out.write("                    <li>Aspect Security</li>\n");
      out.write("                    <li>Ounce Labs</li>\n");
      out.write("                </ul>\n");
      out.write("                </p><br></br>\n");
      out.write("                <p>Did we miss you? Our sincere apologies, as we know there have\n");
      out.write("                    been many contributors over the years. If your name does not\n");
      out.write("                    appear in any of the lists above, please send us a note. We'll\n");
      out.write("                    get you added with no further sacrifices required.</p>\n");
      out.write("            </div>\n");
      out.write("            <div class=\"col-md-6\">\n");
      out.write("                <p>Past Contributors\n");
      out.write("                <ul>\n");
      out.write("                    <li>Dave Cowden (Everything)</li>\n");
      out.write("                    <li>Richard Lawson (Service Layer)</li>\n");
      out.write("                    <li>Keith Gasser (Survey/Security)</li>\n");
      out.write("                    <li>Devin Mayhew (Setup/Admin)</li>\n");
      out.write("                    <li>Li Simon (Developer)</li>\n");
      out.write("                    <li>Ali Looney (UI Design)</li>\n");
      out.write("                    <li>David Anderson (Developer/Design)</li>\n");
      out.write("                    <li>Christopher Blum (Lessons)</li>\n");
      out.write("                    <li>Laurence Casey (Graphics)</li>\n");
      out.write("                    <li>Brian Ciomei (Bug fixes)</li>\n");
      out.write("                    <li>Rogan Dawes (Lessons)</li>\n");
      out.write("                    <li>Erwin Geirnaert (Solutions)</li>\n");
      out.write("                    <li>Aung Knant (Documentation)</li>\n");
      out.write("                    <li>Ryan Knell (Lessons)</li>\n");
      out.write("                    <li>Christine Koppeit (Build)</li>\n");
      out.write("                    <li>Sherif Kousa (Lessons/Documentation)</li>\n");
      out.write("                    <li>Reto Lippuner (Lessons)</li>\n");
      out.write("                    <li>PartNet (Lessons)</li>\n");
      out.write("                    <li>Yiannis Pavlosoglou (Lessons)</li>\n");
      out.write("                    <li>Eric Sheridan (Lessons)</li>\n");
      out.write("                    <li>Alex Smolen (Lessons)</li>\n");
      out.write("                    <li>Chuck Willis (Lessons)</li>\n");
      out.write("                    <li>Marcel Wirth (Lessons)</li>\n");
      out.write("                </ul>\n");
      out.write("                </p>\n");
      out.write("            </div>\n");
      out.write("        </div>\n");
      out.write("    </div>\n");
      out.write("    <div class=\"modal-footer\">\n");
      out.write("        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">Close</button>\n");
      out.write("    </div>\n");
      out.write("</div>\n");
    } catch (java.lang.Throwable t) {
      if (!(t instanceof javax.servlet.jsp.SkipPageException)){
        out = _jspx_out;
        if (out != null && out.getBufferSize() != 0)
          try {
            if (response.isCommitted()) {
              out.flush();
            } else {
              out.clearBuffer();
            }
          } catch (java.io.IOException e) {}
        if (_jspx_page_context != null) _jspx_page_context.handlePageException(t);
        else throw new ServletException(t);
      }
    } finally {
      _jspxFactory.releasePageContext(_jspx_page_context);
    }
  }
}
