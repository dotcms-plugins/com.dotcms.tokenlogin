package com.dotcms.tokenlogin.auth.interceptor;

import java.io.IOException;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.tokenlogin.auth.util.BundleProperties;
import com.dotcms.tokenlogin.auth.util.TokenLoginUtils;
import com.dotmarketing.exception.DotRuntimeException;
import com.dotmarketing.filters.InterceptorFilter;
import com.dotmarketing.util.Logger;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.liferay.portal.model.User;
import com.liferay.portal.util.PortalUtil;
import io.vavr.control.Try;

/**
 * This interceptor is used for handle the a token based login check on DotCMS BE.
 * 
 */
public class TokenLoginInterceptor implements WebInterceptor {


    private static final List<String> BACK_END_URLS = ImmutableList.of("/api/tokenlogin");

    private static final String TOKEN_HEADER = BundleProperties.getProperty("auth.token.header");


    private final TokenLoginUtils tokenLoginUtils;

    public TokenLoginInterceptor() {

        tokenLoginUtils = new TokenLoginUtils();

    }


    @Override
    public String[] getFilters() {
        return new ImmutableList.Builder<String>().addAll(BACK_END_URLS).build().toArray(new String[0]);

    }

    /**
     * This login required will be used for the BE, when the user is on BE, is not logged in and the by
     * pass native=true is not in the query string will redirect to the OAUTH Servlet in order to do the
     * authentication with OAUTH
     */
    @Override
    public Result intercept(final HttpServletRequest request, final HttpServletResponse response) throws IOException {

        try {
            return _intercept(request, response);
        } finally {

        }
    }


    private Result _intercept(final HttpServletRequest request, final HttpServletResponse response) throws IOException {


        setNoCacheHeaders(response);


        Logger.info(this.getClass().getName(), "TokenLogin  request");
        Logger.info(this.getClass().getName(), "TokenLogin: headers----");
        
        Enumeration<String> headers = request.getHeaderNames();
        while (headers.hasMoreElements()) {
            String header = headers.nextElement();
            Logger.info(this.getClass().getName(), header + " : " + request.getHeader(header));
        }
        
        Logger.info(this.getClass().getName(), "/TokenLogin: headers----");


        final String hostName = request.getHeader("x-forwarded-host");
        final String loginToken = request.getHeader(TOKEN_HEADER);
        final String userEmail = request.getHeader("x-forwarded-user");

        Try.run(() -> tokenLoginUtils.updateValidReferers(hostName)).onFailure(e -> {
            throw new DotRuntimeException(e);
        });


        // If we already have a logged in user, continue
        User user = PortalUtil.getUser(request);

        if (null != user && user.isBackendUser()) {
            Logger.info(this.getClass().getName(), "Already have a user:" + user);
            response.sendRedirect("/dotAdmin/");
            return Result.SKIP_NO_CHAIN;
        }

       Map<String,String> userMap= Try.of(()->tokenLoginUtils.authenticateToken(loginToken))
                       .onFailure(e->Logger.warnAndDebug(InterceptorFilter.class, e))
                       .getOrElse(ImmutableMap.of());
        
       if(userMap.isEmpty()) {
            Logger.info(this.getClass().getName(), "Unable to find authentication token");
            response.sendError(403);
            return Result.SKIP_NO_CHAIN;
       }


        user = tokenLoginUtils.validateUser(userMap);


        if (null != user) {
            Logger.info(this.getClass().getName(), "Authenticating User");
            user = tokenLoginUtils.authenticate(request, response, user);

            response.sendRedirect("/dotAdmin/");
            return Result.SKIP_NO_CHAIN;

        }

        response.sendError(403);

        return Result.SKIP_NO_CHAIN;

    } // intercept.


    public void setNoCacheHeaders(HttpServletResponse response) {
        // set no cache on the login page

        Logger.info(this.getClass().getName(), "Login Flow, setting no-cache headers");
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);

    }

}
