/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

import java.security.PrivilegedAction;
import java.security.Provider;

public class GetImplPrivilegedAction implements PrivilegedAction {
    private Provider provider_;

    private String algorithm_;

    private String type_;

    public GetImplPrivilegedAction(String algorithm, String type,
            Provider provider) {
        algorithm_ = algorithm;
        type_ = type;
        provider_ = provider;
    }

    public Object run() {
        ClassLoader cl;
        String className;

        className = Util.resolveAlgorithm(algorithm_, type_, provider_);

        if (className == null) {
            return null;
        }
        try {
            cl = provider_.getClass().getClassLoader();

            return Class.forName(className, true, cl).newInstance();
        } catch (Exception e) {
            return null;
        }
    }
}
