/******************************************************************************* 
 *  Copyright 2008-2010 Amazon Technologies, Inc.
 *  Licensed under the Apache License, Version 2.0 (the "License"); 
 *
 *  You may not use this file except in compliance with the License. 
 *  You may obtain a copy of the License at: http://aws.amazon.com/apache2.0
 *  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR 
 *  CONDITIONS OF ANY KIND, either express or implied. See the License for the 
 *  specific language governing permissions and limitations under the License.
 * ***************************************************************************** 
 */

package com.dotcms.tokenlogin.auth.util;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Properties;
import com.dotmarketing.util.UtilMethods;

/**
 * This class reads configuration values from config.properties file.
 */
public class BundleProperties {

    private static final String PROPERTY_FILE_NAME = "tokenlogin.properties";
    private static Properties properties;

    static {
        properties = new Properties();
        try {
            InputStream in = BundleProperties.class
                    .getResourceAsStream("/" + PROPERTY_FILE_NAME);
            if (in == null) {
                in = BundleProperties.class
                        .getResourceAsStream("/com/dotcms/osgi/util/" + PROPERTY_FILE_NAME);
                if (in == null) {
                    throw new FileNotFoundException(PROPERTY_FILE_NAME + " not found");
                }
            }
            properties.load(in);
        } catch (FileNotFoundException e) {
            System.out.println("FileNotFoundException : " + PROPERTY_FILE_NAME + " not found");
            e.printStackTrace();
        } catch (IOException e) {
            System.out.println("IOException : Can't read " + PROPERTY_FILE_NAME);
            e.printStackTrace();
        }
    }
    public final String[] getArrayValue(final String key) {
        
        return getArrayValue(key, new String[0]);
    }
    
    public final String[] getArrayValue(final String key, final String[] defaultValue) {
        
        return properties.containsKey(key)
                        ? Arrays.stream(properties.getProperty(key).split(","))
                                        .map(String::trim)
                                        .toArray(String[]::new)
                        : defaultValue;
    }
    public static String getProperty(String key) {
        return properties.getProperty(key);
    }

    public static String getProperty(String key, String defaultValue) {
        String x = properties.getProperty(key);
        return (x == null) ? defaultValue : x;
    }

}