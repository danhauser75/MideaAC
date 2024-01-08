package org.openhab.binding.mideaac.internal.handler;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DataSmoother {

    private final Logger logger = LoggerFactory.getLogger(MideaACHandler.class);
    private final HashMap<String, Float> history = new HashMap<String, Float>();
    private final ArrayList<String> managed = new ArrayList<String>();

    private static final DecimalFormat df = new DecimalFormat("0.0");

    public void setManaged(String channelName) {
        if (!managed.contains(channelName)) {
            managed.add(channelName);
        }
    }

    private boolean isManaged(String channelName) {
        if (managed.contains(channelName)) {
            return true;
        }
        return false;
    }

    public Float get(String channelName, Float value) {
        if (!isManaged(channelName)) {
            return value;
        }
        if (!history.containsKey(channelName)) {
            history.put(channelName, value);
            return value;
        } else {
            Float previousvalue = history.get(channelName);
            float avg = average(previousvalue, value);
            history.put(channelName, avg);
            return avg;
        }
    }

    public float average(float previousvalue, float value) {
        return Float.parseFloat(df.format((previousvalue + value) / 2));
    }

    public DataSmoother() {
    }
}
