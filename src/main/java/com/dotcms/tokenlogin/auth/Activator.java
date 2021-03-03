package com.dotcms.tokenlogin.auth;

import org.osgi.framework.BundleContext;
import com.dotcms.filters.interceptor.FilterWebInterceptorProvider;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.filters.interceptor.WebInterceptorDelegate;
import com.dotcms.tokenlogin.auth.interceptor.TokenLoginInterceptor;
import com.dotmarketing.filters.InterceptorFilter;
import com.dotmarketing.osgi.GenericBundleActivator;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;

public class Activator extends GenericBundleActivator {

    private WebInterceptor[] webInterceptors = {new TokenLoginInterceptor()};


    final WebInterceptorDelegate delegate =
                    FilterWebInterceptorProvider.getInstance(Config.CONTEXT).getDelegate(InterceptorFilter.class);

    public void start(org.osgi.framework.BundleContext context) throws Exception {


        Logger.info(Activator.class.getName(), "Starting OSGi " + TokenLoginInterceptor.class.getName());



        Config.setProperty("PREVENT_SESSION_FIXATION_ON_LOGIN", false);


        for (WebInterceptor webIn : webInterceptors) {
            Logger.info(Activator.class.getName(), "Adding the " + webIn.getName());
            delegate.addFirst(webIn);
        }

    }

    @Override
    public void stop(BundleContext context) throws Exception {

        unregisterServices(context);


        for (WebInterceptor webIn : webInterceptors) {
            Logger.info(Activator.class.getName(), "Removing the " + webIn.getClass().getName());
            delegate.remove(webIn.getName(), true);
        }

    }

}
