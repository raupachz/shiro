package org.apache.shiro.web.mgt;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.subject.WebSubjectContext;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DatabaseCookieRememberMeManager extends CookieRememberMeManager {

    private static transient final Logger log = LoggerFactory.getLogger(DatabaseCookieRememberMeManager.class);

    private DataSource dataSource;

    private String selectPrincipalsQuery = "select Principal from Principals where Nonce = ?";

    private String insertPrincipalQuery = "insert ignore into Principals values (?, ?)";

    @Override
    public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {

        if (!WebUtils.isHttp(subjectContext)) {
            if (log.isDebugEnabled()) {
                String msg = "SubjectContext argument is not an HTTP-aware instance.  This is required to obtain a "
                        + "servlet request and response in order to retrieve the rememberMe cookie. Returning "
                        + "immediately and ignoring rememberMe operation.";
                log.debug(msg);
            }
            return null;
        }

        WebSubjectContext wsc = (WebSubjectContext) subjectContext;
        HttpServletRequest request = WebUtils.getHttpRequest(wsc);
        HttpServletResponse response = WebUtils.getHttpResponse(wsc);

        Boolean removed = (Boolean) request.getAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY);
        if (removed != null && removed) {
            return null;
        }

        String nonce = getCookie().readValue(request, response);

        if (nonce == null || Cookie.DELETED_COOKIE_VALUE.equals(nonce)) {
            return null;
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Acquired String encoded identity [" + nonce + "]");
            }

            List<String> principials = loadPrincipals(nonce);
            if (principials.isEmpty()) {
                return null; // did not found any matching principal
            }

            SimplePrincipalCollection principalCollection = new SimplePrincipalCollection(principials, "whatever");
            return principalCollection;
        }
    }

    @Override
    protected void rememberIdentity(Subject subject, PrincipalCollection accountPrincipals) {

        if (!WebUtils.isHttp(subject)) {
            if (log.isDebugEnabled()) {
                String msg = "Subject argument is not an HTTP-aware instance.  This is required to obtain a servlet "
                        + "request and response in order to set the rememberMe cookie. Returning immediately and "
                        + "ignoring rememberMe operation.";
                log.debug(msg);
            }
            return;
        }

        HttpServletRequest request = WebUtils.getHttpRequest(subject);
        HttpServletResponse response = WebUtils.getHttpResponse(subject);

        String nonce = generateNonce();

        storePrincipals(accountPrincipals, nonce);

        Cookie template = getCookie();
        Cookie cookie = new SimpleCookie(template);
        cookie.setValue(nonce);
        cookie.saveTo(request, response);
    }

    /*
     * Loads all the principals that are stored for the given nonce
     */
    private List<String> loadPrincipals(String nonce) {
        List<String> principals = new ArrayList<String>();
        Connection connection = null;
        try {
            connection = dataSource.getConnection();
            PreparedStatement ps = connection.prepareStatement(selectPrincipalsQuery);
            ps.setString(1, nonce);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                principals.add(rs.getString(1));
            }
        } catch (SQLException e) {
            log.error("Can't load principals from DataSource.", e);
        } finally {
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException ignore) {
                }
            }
        }
        return principals;
    }

    // Generates a nonce, session id or whatever you like to call it
    private String generateNonce() {
        SecureRandomNumberGenerator srng = new SecureRandomNumberGenerator();
        ByteSource bytes = srng.nextBytes();
        return bytes.toBase64();
    }

    private void storePrincipals(PrincipalCollection principals, String nonce) {
        Connection connection = null;
        try {
            connection = dataSource.getConnection();
            PreparedStatement ps = connection.prepareStatement(insertPrincipalQuery);
            for (Iterator iter = principals.iterator(); iter.hasNext();) {
                String principal = iter.next().toString();
                ps.setString(1, principal);
                ps.setString(2, nonce);
                ps.addBatch();
            }
            ps.executeBatch();
        } catch (SQLException e) {
            log.error("Can't load principals from DataSource.", e);
        } finally {
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException ignore) {
                }
            }
        }
    }

    // Getters and Setters
    public DataSource getDataSource() {
        return dataSource;
    }

    public void setDataSource(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public String getSelectPrincipalsQuery() {
        return selectPrincipalsQuery;
    }

    public void setSelectPrincipalsQuery(String selectPrincipalsQuery) {
        this.selectPrincipalsQuery = selectPrincipalsQuery;
    }

}
