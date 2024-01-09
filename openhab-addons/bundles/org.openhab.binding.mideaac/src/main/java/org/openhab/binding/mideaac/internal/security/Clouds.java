package org.openhab.binding.mideaac.internal.security;

import java.util.HashMap;

public class Clouds {

    private final HashMap<String, Cloud> clouds;

    public Clouds() {
        clouds = new HashMap<>();
    }

    private Cloud add(String email, String password, CloudProvider cloudProvider) {
        String key = email + password + cloudProvider.getName();
        Cloud cloud = new Cloud(email, password, cloudProvider);
        clouds.put(key, cloud);
        return cloud;
    }

    public Cloud get(String email, String password, CloudProvider cloudProvider) {
        String key = email + password + cloudProvider.getName();
        if (clouds.containsKey(key)) {
            return clouds.get(key);
        }
        return add(email, password, cloudProvider);
    }
}
