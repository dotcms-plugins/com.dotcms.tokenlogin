package com.dotcms.tokenlogin.auth.util;


import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.dotcms.business.WrapInTransaction;
import com.dotcms.enterprise.PasswordFactoryProxy;
import com.dotcms.http.CircuitBreakerUrl;
import com.dotcms.util.SecurityUtils;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.DotStateException;
import com.dotmarketing.business.Layout;
import com.dotmarketing.business.LayoutAPI;
import com.dotmarketing.business.Role;
import com.dotmarketing.cms.factories.PublicEncryptionFactory;
import com.dotmarketing.exception.DotRuntimeException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
import com.dotmarketing.util.UtilMethods;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.liferay.portal.model.User;
import io.vavr.collection.HashMap;
import io.vavr.control.Try;


public class TokenLoginUtils {

    private static final String AUTH_TOKEN = BundleProperties.getProperty("tokenlogin.auth.token");
    
    
    public void updateValidReferers(String hostName) throws NoSuchFieldException, SecurityException,
                    IllegalArgumentException, IllegalAccessException, NoSuchMethodException, InvocationTargetException {

        Logger.info(this.getClass().getName(), "Updating valid referers with: " + hostName);
        final SecurityUtils utils = new SecurityUtils();

        final Method method = utils.getClass().getDeclaredMethod("loadIgnoreHosts", null);

        method.setAccessible(true);
        List<String> allowedList = (List<String>) method.invoke(utils, null);
        if (allowedList == null) {
            allowedList = new ArrayList<>();
        }
        if (allowedList.contains(hostName)) {
            return;
        }

        // Get field instance
        final Field field = SecurityUtils.class.getDeclaredField("IGNORE_REFERER_FOR_HOSTS");
        field.setAccessible(true); // Suppress Java language access checking


        final List<String> newIgnoreList = new ArrayList<>(allowedList);
        newIgnoreList.add(hostName);
        Logger.info(this.getClass().getName(), "adding : " + hostName);


        // Set value
        field.set(null, newIgnoreList);

        allowedList = (List<String>) method.invoke(utils, null);
        if (!allowedList.contains(hostName)) {
            throw new DotRuntimeException("Unable to add " + hostName + " to the allowed referer list");
        }
    }
    
    
    
    

    public User validateUser(Map<String,String> userInfo) {
        String userEmail = userInfo.get("emailAddress");
        
        User user = Try.of(()->APILocator.getUserAPI().loadByUserByEmail(userEmail, APILocator.systemUser(), false)).getOrNull();
        if(user==null) {
            user = createUser(userEmail);
        }

        if(!user.isActive()) {
            user.setActive(true);
            saveUser(user);
        }
        
        if(user.hasConsoleAccess() && user.isAdmin()) {
            return user;
        }
        
        grantAdminRoles(user);
        grantAllLayouts(user);
        
        
        return user;
        

    }

    @WrapInTransaction
    private User saveUser(User user) {
        
        Try.run(()->APILocator.getUserAPI().save(user, APILocator.systemUser(), false)).onFailure(e->{throw new DotRuntimeException(e);});
        return user;
    }
    
    
    @WrapInTransaction
    private boolean grantAdminRoles(User user) {
        if(user.isAdmin() && user.isBackendUser()) {
            return true;
        }
        Try.run(()->{
            if(!user.isAdmin()) {
                Role role = APILocator.getRoleAPI().loadCMSAdminRole();
                APILocator.getRoleAPI().addRoleToUser(role, user);
                role = APILocator.getRoleAPI().loadBackEndUserRole();
                APILocator.getRoleAPI().addRoleToUser(role, user);
                
            }
        }).onFailure(e->new DotRuntimeException(e));
        return true;
    }
    
    

    
    @WrapInTransaction
    private boolean grantAllLayouts(final User user) {
        LayoutAPI api = APILocator.getLayoutAPI();
        final List<Layout> allLayouts = Try.of(() -> api.findAllLayouts()).getOrElseThrow(e->new DotStateException("Unable to find user role for user:" + user.getUserId()));
        final List<Layout> myLayouts = Try.of(()->api.loadLayoutsForUser(user)).getOrElseThrow(e->new DotRuntimeException(e));
        final Role userRole= Try.of(() -> APILocator.getRoleAPI().loadRoleByKey(user.getUserId())).getOrElseThrow(e->new DotStateException("Unable to find user role for user:" + user.getUserId()));

        Set<String> myPortlets = new HashSet<>();
        Set<String> allPortlets = new HashSet<>();
        myLayouts.forEach(l->myPortlets.addAll(l.getPortletIds()));
        allLayouts.forEach(l->allPortlets.addAll(l.getPortletIds()));
        if(myPortlets.size()>=allPortlets.size()) {
            return true;
        }
        
        allLayouts
            .stream()
            .filter(l-> !myPortlets.containsAll(l.getPortletIds()))
            .forEach(l->{
                Try.run(()->APILocator.getRoleAPI().addLayoutToRole(l,userRole)).onFailure(e->{throw new DotRuntimeException(e);});
                myPortlets.addAll(l.getPortletIds());
            });



        allLayouts.stream().filter(l->!myLayouts.contains(l)).forEach(l->{
            
        });
        return true;
    }

    final String FAILURE = "FAILURE";
    final String validationUrl = BundleProperties.getProperty("auth.token.validationUrl");
    
    
    
    /**
     * Default method implementation to extract the access token from the request token json response
     * @throws IOException 
     */
    public Map<String,String> authenticateToken(final String tokenString) throws IOException {
        if (UtilMethods.isEmpty(tokenString)) {
           throw new DotRuntimeException("unable to parse jwt token");
         }
        
        
        Map<String,String> tokenMap = Try.of(()->(Map<String,String>) new ObjectMapper().readValue(tokenString, Map.class)).getOrElseThrow(e->new DotRuntimeException("unable to parse jwt token", e)); 
        
        
        

        Logger.info(this.getClass().getName(), "trying " + validationUrl +" with token " + tokenString);
        Map<String,String> headers= ImmutableMap.of("Authorization", "Bearer " + tokenString);
        
        final String response = Try.of(()->CircuitBreakerUrl
                        .builder()
                        .setMethod(com.dotcms.http.CircuitBreakerUrl.Method.GET)
                        .setHeaders(headers)
                        .setUrl(validationUrl)
                        .setTimeout(5000)
                        .build()
                        .doString()).getOrElse(FAILURE);
        
        Logger.info(this.getClass().getName(), "got " + response);
        
        if (FAILURE.equals(response)) {
            throw new DotRuntimeException("unable to parse jwt token");
        }

        return tokenMap;

        


    }


    /**
     * This method gets the user from the remote service and either creates them in dotCMS and/or
     * updates
     *
     * @return User
     * @throws JsonProcessingException
     * @throws JsonMappingException
     */
    public User authenticate(final HttpServletRequest request, final HttpServletResponse response, User user) {


        // Authenticate to dotCMS
        Logger.info(this.getClass().getName(), "Doing Token login!");


        APILocator.getLoginServiceAPI().doCookieLogin(PublicEncryptionFactory.encryptString(user.getUserId()), request,
                        response, false);

        Logger.info(this.getClass().getName(), "Finishing Token login!");


        return user;
    } // authenticate.


    public void setSystemRoles(User user, boolean frontEnd) {

        final Role roleToAdd = frontEnd ? Try.of(() -> APILocator.getRoleAPI().loadLoggedinSiteRole()).getOrNull()
                        : Try.of(() -> APILocator.getRoleAPI().loadBackEndUserRole()).getOrNull();

        if (roleToAdd != null) {
            Try.run(() -> APILocator.getRoleAPI().addRoleToUser(roleToAdd, user)).onFailure(e -> {
                Logger.warn(TokenLoginUtils.class.getName(), e.getMessage(), e);
            });
        }


    }


    public User createUser(final String emailAddress) {

        final String userId = UUIDGenerator.generateUuid();
        final String name = emailAddress.split("@")[0];
        final String nickName = name.indexOf(".")<0 ? name : name.split(".")[0];
        final String lastName = "dotCMS Support";
        
        try {
            final User user = APILocator.getUserAPI().createUser(userId, emailAddress);
            user.setNickName(nickName);
            user.setFirstName(name);
            user.setLastName(lastName);
            user.setActive(true);

            user.setCreateDate(new Date());

            user.setPassword(PasswordFactoryProxy
                            .generateHash(UUIDGenerator.generateUuid() + "/" + UUIDGenerator.generateUuid()));
            user.setPasswordEncrypted(true);
            APILocator.getUserAPI().save(user, APILocator.systemUser(), false);

            return user;
        } catch (Exception e) {
            throw new DotRuntimeException(e);
        }
    } // createUser.




}
