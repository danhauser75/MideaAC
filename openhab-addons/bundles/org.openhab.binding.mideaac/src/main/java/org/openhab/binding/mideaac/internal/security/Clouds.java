package org.openhab.binding.mideaac.internal.security;

import java.util.HashMap;

public class Clouds {

    private final HashMap<Integer, Cloud> clouds;

    public Clouds() {
        clouds = new HashMap<Integer, Cloud>();
    }

    private Cloud add(String email, String password, CloudProvider cloudProvider) {
        int hash = (email + password + cloudProvider.getName()).hashCode();
        Cloud cloud = new Cloud(email, password, cloudProvider);
        clouds.put(hash, cloud);
        return cloud;
    }

    public Cloud get(String email, String password, CloudProvider cloudProvider) {
        int hash = (email + password + cloudProvider.getName()).hashCode();
        if (clouds.containsKey(hash)) {
            return clouds.get(hash);
        }
        return add(email, password, cloudProvider);
    }
}
