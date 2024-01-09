/**
 * Copyright (c) 2010-2021 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.mideaac.internal.handler;

import static org.openhab.binding.mideaac.internal.MideaACBindingConstants.*;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.measure.Unit;
import javax.measure.quantity.Temperature;
import javax.measure.spi.SystemOfUnits;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.jetty.client.HttpClient;
import org.openhab.binding.mideaac.internal.MideaACConfiguration;
import org.openhab.binding.mideaac.internal.Utils;
import org.openhab.binding.mideaac.internal.discovery.DiscoveryHandler;
import org.openhab.binding.mideaac.internal.discovery.MideaACDiscoveryService;
import org.openhab.binding.mideaac.internal.handler.CommandBase.FanSpeed;
import org.openhab.binding.mideaac.internal.handler.CommandBase.OperationalMode;
import org.openhab.binding.mideaac.internal.handler.CommandBase.SwingMode;
import org.openhab.binding.mideaac.internal.security.Cloud;
import org.openhab.binding.mideaac.internal.security.CloudProvider;
import org.openhab.binding.mideaac.internal.security.Clouds;
import org.openhab.binding.mideaac.internal.security.Decryption8370Result;
import org.openhab.binding.mideaac.internal.security.Security;
import org.openhab.binding.mideaac.internal.security.Security.MsgType;
import org.openhab.binding.mideaac.internal.security.TokenKey;
import org.openhab.core.config.core.Configuration;
import org.openhab.core.config.discovery.DiscoveryResult;
import org.openhab.core.i18n.UnitProvider;
import org.openhab.core.library.types.DecimalType;
import org.openhab.core.library.types.OnOffType;
import org.openhab.core.library.types.QuantityType;
import org.openhab.core.library.types.StringType;
import org.openhab.core.library.unit.ImperialUnits;
import org.openhab.core.library.unit.SIUnits;
import org.openhab.core.thing.Channel;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.binding.BaseThingHandler;
import org.openhab.core.types.Command;
import org.openhab.core.types.RefreshType;
import org.openhab.core.types.State;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@link MideaACHandler} is responsible for handling commands, which are
 * sent to one of the channels.
 *
 * @author Jacek Dobrowolski
 */
// @NonNullByDefault
public class MideaACHandler extends BaseThingHandler implements DiscoveryHandler {

    private final Logger logger = LoggerFactory.getLogger(MideaACHandler.class);

    private MideaACConfiguration configuration;
    // private MideaACConfiguration configuration;

    public MideaACConfiguration getConfiguration() {
        return configuration;
    }

    public void setConfiguration(MideaACConfiguration configuration) {
        this.configuration = configuration;
    }

    private Map<String, String> properties = null;

    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }

    private String ipAddress = null;
    private String ipPort = null;
    private String deviceId = null;
    private int version = 0;

    private final DataSmoother dataHistory = new DataSmoother();

    private @Nullable CloudProvider cloudProvider = null;
    private @Nullable Security security;

    public @Nullable CloudProvider getCloudProvider() {
        return cloudProvider;
    }

    public @Nullable Security getSecurity() {
        return security;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    private static final StringType OPERATIONAL_MODE_OFF = new StringType("OFF");
    private static final StringType OPERATIONAL_MODE_AUTO = new StringType("AUTO");
    private static final StringType OPERATIONAL_MODE_COOL = new StringType("COOL");
    private static final StringType OPERATIONAL_MODE_DRY = new StringType("DRY");
    private static final StringType OPERATIONAL_MODE_HEAT = new StringType("HEAT");
    private static final StringType OPERATIONAL_MODE_FAN_ONLY = new StringType("FAN_ONLY");

    private static final StringType FAN_SPEED_OFF = new StringType("OFF");
    private static final StringType FAN_SPEED_SILENT = new StringType("SILENT");
    private static final StringType FAN_SPEED_LOW = new StringType("LOW");
    private static final StringType FAN_SPEED_MEDIUM = new StringType("MEDIUM");
    private static final StringType FAN_SPEED_HIGH = new StringType("HIGH");
    private static final StringType FAN_SPEED_AUTO = new StringType("AUTO");

    private static final StringType SWING_MODE_OFF = new StringType("OFF");
    private static final StringType SWING_MODE_VERTICAL = new StringType("VERTICAL");
    private static final StringType SWING_MODE_HORIZONTAL = new StringType("HORIZONTAL");
    private static final StringType SWING_MODE_BOTH = new StringType("BOTH");
    private final Clouds clouds;

    private final ConnectionManager connectionManager;

    private final SystemOfUnits systemOfUnits;

    private final HttpClient httpClient;

    private ConnectionManager getConnectionManager() {
        return connectionManager;
    }

    private @Nullable Response getLastResponse() {
        return getConnectionManager().getLastResponse();
    }

    public MideaACHandler(Thing thing, String ipv4Address, UnitProvider unitProvider, HttpClient httpClient,
            Clouds clouds) {
        super(thing);
        this.thing = thing;
        this.systemOfUnits = unitProvider.getMeasurementSystem();
        this.httpClient = httpClient;
        this.clouds = clouds;
        dataHistory.setManaged(CHANNEL_OUTDOOR_TEMPERATURE);
        dataHistory.setManaged(CHANNEL_INDOOR_TEMPERATURE);
        connectionManager = new ConnectionManager(ipv4Address, this);
    }

    public Clouds getClouds() {
        return clouds;
    }

    protected boolean isImperial() {
        return systemOfUnits instanceof ImperialUnits;
    }

    @Override
    public void dispose() {
        super.dispose();
        getConnectionManager().dispose();
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
        logger.debug("Handling channelUID {} with command {}", channelUID.getId(), command.toString());

        if (command instanceof RefreshType) {
            connectionManager.requestStatus(true);
            return;
        }

        if (getLastResponse() == null) {
            markOfflineWithMessage(ThingStatusDetail.COMMUNICATION_ERROR,
                    "Device not responding with its status. Last response was null");
            return;
        }

        switch (channelUID.getId()) {
            case CHANNEL_POWER -> handlePower(command);
            case CHANNEL_OPERATIONAL_MODE -> handleOperationalMode(command);
            case CHANNEL_TARGET_TEMPERATURE -> handleTargetTemperature(command);
            case CHANNEL_FAN_SPEED -> handleFanSpeed(command);
            case CHANNEL_ECO_MODE -> handleEcoMode(command);
            case CHANNEL_TURBO_MODE -> handleTurboMode(command);
            case CHANNEL_SWING_MODE -> handleSwingMode(command);
            case CHANNEL_SCREEN_DISPLAY -> handleScreenDisplay(command);
            case CHANNEL_TEMP_UNIT -> handleTempUnit(command);
            default -> logger.debug("Unexpected channelUID '{}' has received with command '{}'", channelUID.getId(),
                    command.toString());
        }
    }

    public void handlePower(Command command) {
        CommandSet commandSet = CommandSet.fromResponse(getLastResponse());

        if (command.equals(OnOffType.OFF)) {
            commandSet.setPowerState(false);
        } else if (command.equals(OnOffType.ON)) {
            commandSet.setPowerState(true);
        } else {
            logger.debug("Unknown power state command: {}", command);
            return;
        }

        getConnectionManager().sendCommandAndMonitor(commandSet);
    }

    public void handleOperationalMode(Command command) {
        CommandSet commandSet = CommandSet.fromResponse(getLastResponse());

        commandSet.setPowerState(true);

        if (command instanceof StringType) {
            if (command.equals(OPERATIONAL_MODE_OFF)) {
                commandSet.setPowerState(false);
                return;
            } else if (command.equals(OPERATIONAL_MODE_AUTO)) {
                commandSet.setOperationalMode(OperationalMode.AUTO);
            } else if (command.equals(OPERATIONAL_MODE_COOL)) {
                commandSet.setOperationalMode(OperationalMode.COOL);
            } else if (command.equals(OPERATIONAL_MODE_DRY)) {
                commandSet.setOperationalMode(OperationalMode.DRY);
            } else if (command.equals(OPERATIONAL_MODE_HEAT)) {
                commandSet.setOperationalMode(OperationalMode.HEAT);
            } else if (command.equals(OPERATIONAL_MODE_FAN_ONLY)) {
                commandSet.setOperationalMode(OperationalMode.FAN_ONLY);
            } else {
                logger.debug("Unknown operational mode command: {}", command);
                return;
            }
        }

        getConnectionManager().sendCommandAndMonitor(commandSet);
    }

    private static float convertTargetCelsiusTemperatureToInRange(float temperature) {
        if (temperature < 17.0f) {
            return 17.0f;
        }
        if (temperature > 30.0f) {
            return 30.0f;
        }

        return temperature;
    }

    private static float convertTargetFahrenheitTemperatureToInRange(float temperature) {
        if (temperature < 62.0f) {
            return 62.0f;
        }
        if (temperature > 86.0f) {
            return 86.0f;
        }

        return temperature;
    }

    public void handleTargetTemperature(Command command) {
        if (command == null) {
            logger.debug("handleTargetTemperature command was null");
            return;
        }
        Response lastResponse = getLastResponse();
        if (lastResponse == null) {
            logger.debug("handleTargetTemperature lastResponse was null");
            return;
        }
        CommandSet commandSet = CommandSet.fromResponse(lastResponse);

        if (command instanceof DecimalType) {
            QuantityType<Temperature> quantity = new QuantityType<>(((DecimalType) command).doubleValue(),
                    lastResponse.getTempUnit() == true ? ImperialUnits.FAHRENHEIT : SIUnits.CELSIUS);
            commandSet.setPowerState(true);
            if (lastResponse.getTempUnit() == true) {
                // F
                if (isImperial()) {
                    logger.debug("handleTargetTemperature: Set field of type Integer F > F");
                    commandSet.setTargetTemperature(convertTargetFahrenheitTemperatureToInRange(quantity.floatValue()));
                } else {
                    logger.debug("handleTargetTemperature: Set field of type Integer C > F");
                    commandSet.setTargetTemperature(convertTargetCelsiusTemperatureToInRange(
                            quantity.toUnit(ImperialUnits.FAHRENHEIT).floatValue()));
                }
            } else {
                if (isImperial()) {
                    logger.debug("handleTargetTemperature: Set field of type Integer F > C");
                    commandSet.setTargetTemperature(
                            convertTargetFahrenheitTemperatureToInRange(quantity.toUnit(SIUnits.CELSIUS).floatValue()));
                } else {
                    logger.debug("handleTargetTemperature: Set field of type Integer C > C");
                    commandSet.setTargetTemperature(convertTargetCelsiusTemperatureToInRange(quantity.floatValue()));
                }
            }
            getConnectionManager().sendCommandAndMonitor(commandSet);
        } else if (command instanceof QuantityType) {
            commandSet.setPowerState(true);

            QuantityType<?> quantity = (QuantityType<?>) command;
            Unit<?> unit = quantity.getUnit();
            logger.debug(
                    "handleTargetTemperature: Set field of type Integer to value of item QuantityType with unit {}",
                    unit);
            if (unit.equals(ImperialUnits.FAHRENHEIT) || unit.equals(SIUnits.CELSIUS)) {
                if (lastResponse.getTempUnit() == true && unit.equals(ImperialUnits.FAHRENHEIT)) {
                    commandSet.setTargetTemperature(convertTargetFahrenheitTemperatureToInRange(quantity.floatValue()));
                } else if (lastResponse.getTempUnit() == true && unit.equals(SIUnits.CELSIUS)) {
                    commandSet.setTargetTemperature(convertTargetFahrenheitTemperatureToInRange(
                            quantity.toUnit(ImperialUnits.FAHRENHEIT).floatValue()));
                } else if (lastResponse.getTempUnit() == false && unit.equals(SIUnits.CELSIUS)) {
                    commandSet.setTargetTemperature(convertTargetCelsiusTemperatureToInRange(quantity.floatValue()));
                } else if (lastResponse.getTempUnit() == false && unit.equals(ImperialUnits.FAHRENHEIT)) {
                    commandSet.setTargetTemperature(
                            convertTargetCelsiusTemperatureToInRange(quantity.toUnit(SIUnits.CELSIUS).floatValue()));
                }
                getConnectionManager().sendCommandAndMonitor(commandSet);
            }
        } else {
            logger.debug("handleTargetTemperature unsupported commandType:{}", command.getClass().getTypeName());
        }
    }

    public void handleFanSpeed(Command command) {
        CommandSet commandSet = CommandSet.fromResponse(getLastResponse());

        if (command instanceof StringType) {
            commandSet.setPowerState(true);
            if (command.equals(FAN_SPEED_OFF)) {
                commandSet.setPowerState(false);
            } else if (command.equals(FAN_SPEED_SILENT)) {
                if (getVersion() == 2) {
                    commandSet.setFanSpeed(FanSpeed.SILENT2);
                } else if (getVersion() == 3) {
                    commandSet.setFanSpeed(FanSpeed.SILENT3);
                }
            } else if (command.equals(FAN_SPEED_LOW)) {
                if (getVersion() == 2) {
                    commandSet.setFanSpeed(FanSpeed.LOW2);
                } else if (getVersion() == 3) {
                    commandSet.setFanSpeed(FanSpeed.LOW3);
                }
            } else if (command.equals(FAN_SPEED_MEDIUM)) {
                if (getVersion() == 2) {
                    commandSet.setFanSpeed(FanSpeed.MEDIUM2);
                } else if (getVersion() == 3) {
                    commandSet.setFanSpeed(FanSpeed.MEDIUM3);
                }
            } else if (command.equals(FAN_SPEED_HIGH)) {
                if (getVersion() == 2) {
                    commandSet.setFanSpeed(FanSpeed.HIGH2);
                } else if (getVersion() == 3) {
                    commandSet.setFanSpeed(FanSpeed.HIGH3);
                }
            } else if (command.equals(FAN_SPEED_AUTO)) {
                if (getVersion() == 2) {
                    commandSet.setFanSpeed(FanSpeed.AUTO2);
                } else if (getVersion() == 3) {
                    commandSet.setFanSpeed(FanSpeed.AUTO3);
                }
            } else {
                logger.debug("Unknown fan speed command: {}", command);
                return;
            }
        }

        getConnectionManager().sendCommandAndMonitor(commandSet);
    }

    public void handleEcoMode(Command command) {
        CommandSet commandSet = CommandSet.fromResponse(getLastResponse());

        if (command.equals(OnOffType.OFF)) {
            commandSet.setEcoMode(false);
        } else if (command.equals(OnOffType.ON)) {
            commandSet.setEcoMode(true);
        } else {
            logger.debug("Unknown eco mode command: {}", command);
            return;
        }

        getConnectionManager().sendCommandAndMonitor(commandSet);
    }

    public void handleSwingMode(Command command) {
        if (getVersion() == 3) {
            logger.debug("Setting Swing Mode for version 3 is not supported by protocol (LAN and Cloud)");
            return;
        }
        CommandSet commandSet = CommandSet.fromResponse(getLastResponse());

        commandSet.setPowerState(true);

        if (command instanceof StringType) {
            if (command.equals(SWING_MODE_OFF)) {
                commandSet.setSwingMode(SwingMode.OFF);
            } else if (command.equals(SWING_MODE_VERTICAL)) {
                commandSet.setSwingMode(SwingMode.VERTICAL);
            } else if (command.equals(SWING_MODE_HORIZONTAL)) {
                commandSet.setSwingMode(SwingMode.HORIZONTAL);
            } else if (command.equals(SWING_MODE_BOTH)) {
                commandSet.setSwingMode(SwingMode.BOTH);
            } else {
                logger.debug("Unknown swing mode command: {}", command);
                return;
            }
        }

        getConnectionManager().sendCommandAndMonitor(commandSet);
    }

    public void handleTurboMode(Command command) {
        CommandSet commandSet = CommandSet.fromResponse(getLastResponse());

        commandSet.setPowerState(true);

        if (command.equals(OnOffType.OFF)) {
            commandSet.setTurboMode(false);
        } else if (command.equals(OnOffType.ON)) {
            commandSet.setTurboMode(true);
        } else {
            logger.debug("Unknown turbo mode command: {}", command);
            return;
        }

        getConnectionManager().sendCommandAndMonitor(commandSet);
    }

    public void handleScreenDisplay(Command command) {
        CommandSet commandSet = CommandSet.fromResponse(getLastResponse());

        if (command.equals(OnOffType.OFF)) {
            commandSet.setScreenDisplay(false);
        } else if (command.equals(OnOffType.ON)) {
            commandSet.setScreenDisplay(true);
        } else {
            logger.debug("Unknown screen display command: {}", command);
            return;
        }

        getConnectionManager().sendCommandAndMonitor(commandSet);
    }

    public void handleTempUnit(Command command) {
        CommandSet commandSet = CommandSet.fromResponse(getLastResponse());

        if (command.equals(OnOffType.OFF)) {
            commandSet.setFahrenheit(false);
        } else if (command.equals(OnOffType.ON)) {
            commandSet.setFahrenheit(true);
        } else {
            logger.debug("Unknown temperature unit/farenheit command: {}", command);
            return;
        }

        getConnectionManager().sendCommandAndMonitor(commandSet);
    }

    @Override
    public void initialize() {
        // connectionManager.disconnect();
        getConnectionManager().disconnect();

        setCloudProvider(CloudProvider.getCloudProvider("MSmartHome"));
        setSecurity(new Security(cloudProvider));

        setConfiguration(getConfigAs(MideaACConfiguration.class));
        // properties = editProperties();
        setProperties(editProperties());
        logger.debug("MideaACHandler config for {} is {}", thing.getUID(), getConfiguration());

        if (!getConfiguration().isValid()) {
            logger.warn("Configuration invalid for {}", thing.getUID());
            if (getConfiguration().isDiscoveryNeeded()) {
                logger.warn("Discovery needed, thing '{}' is discovering....", thing.getUID());
                updateStatus(ThingStatus.UNKNOWN, ThingStatusDetail.CONFIGURATION_PENDING,
                        "Configuration missing, discovery needed. Discovering...");
                MideaACDiscoveryService discoveryService = new MideaACDiscoveryService();

                // discoveryService.setSecurity(this.getSecurity());
                try {
                    discoveryService.discoverThing(getConfiguration().getIpAddress(), this);
                } catch (Exception e) {
                    logger.error("Discovery failure for {}: {}", thing.getUID(), e.getMessage());
                }
                return;
            } else {
                logger.debug("MideaACHandler config of {} is invalid. Check configuration", thing.getUID());
                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                        "Invalid MideaAC config. Check configuration.");
                return;
            }
        } else {
            logger.debug("Configuration valid for {}", thing.getUID());
        }

        ipAddress = getConfiguration().getIpAddress();
        ipPort = getConfiguration().getIpPort();
        deviceId = getConfiguration().getDeviceId();
        version = Integer.parseInt(getProperties().get(PROPERTY_VERSION).toString());

        logger.debug("IPAddress: {}", ipAddress);
        logger.debug("IPPort: {}", ipPort);
        logger.debug("ID: {}", deviceId);
        logger.debug("Version: {}", version);

        updateStatus(ThingStatus.UNKNOWN);

        connectionManager.connect();
    }

    @Override
    public void discovered(DiscoveryResult discoveryResult) {
        logger.debug("Discovered {}", thing.getUID());

        Configuration updatedConfiguration = editConfiguration();

        updatedConfiguration.put(CONFIG_DEVICEID, discoveryResult.getProperties().get(CONFIG_DEVICEID).toString());
        updatedConfiguration.put(CONFIG_IP_PORT, discoveryResult.getProperties().get(CONFIG_IP_PORT).toString());

        updateConfiguration(updatedConfiguration);

        setProperties(editProperties());
        getProperties().put(PROPERTY_VERSION, discoveryResult.getProperties().get(PROPERTY_VERSION).toString());
        getProperties().put(PROPERTY_SN, discoveryResult.getProperties().get(PROPERTY_SN).toString());
        getProperties().put(PROPERTY_SSID, discoveryResult.getProperties().get(PROPERTY_SSID).toString());
        getProperties().put(PROPERTY_TYPE, discoveryResult.getProperties().get(PROPERTY_TYPE).toString());
        updateProperties(getProperties());
        initialize();
    }

    /*
     * Manage the ONLINE/OFFLINE status of the thing
     */
    private void markOnline() {
        if (!isOnline()) {
            logger.debug("Changing status of {} from {}({}) to ONLINE", thing.getUID(), getStatus(), getDetail());
            updateStatus(ThingStatus.ONLINE);
            // logger.debug(Arrays.toString(Thread.currentThread().getStackTrace()).replace(',', '\n'));

        }
    }

    private void markOffline() {
        if (isOnline()) {
            logger.debug("Changing status of {} from {}({}) to OFFLINE", thing.getUID(), getStatus(), getDetail());
            updateStatus(ThingStatus.OFFLINE);
            // logger.debug(Arrays.toString(Thread.currentThread().getStackTrace()).replace(',', '\n'));
        }
    }

    private void markOfflineWithMessage(ThingStatusDetail statusDetail, String statusMessage) {
        // If it's offline with no detail or if it's not offline, mark it offline with detailed status
        if ((isOffline() && getDetail() == ThingStatusDetail.NONE)
                || (isOffline() && !statusMessage.equals(getDescription())) || !isOffline()) {
            logger.debug("Changing status of {} from {}({}) to OFFLINE({})", thing.getUID(), getStatus(), getDetail(),
                    statusDetail);
            if (isOffline()) {
                updateStatus(ThingStatus.UNKNOWN);
            }
            try {
                Thread.sleep(250);
            } catch (InterruptedException e) {
            }

            updateStatus(ThingStatus.OFFLINE, statusDetail, statusMessage);
            // logger.debug(Arrays.toString(Thread.currentThread().getStackTrace()).replace(',', '\n'));
            return;
        }
    }

    private boolean isOnline() {
        return thing.getStatus().equals(ThingStatus.ONLINE);
    }

    private boolean isOffline() {
        return thing.getStatus().equals(ThingStatus.OFFLINE);
    }

    private ThingStatus getStatus() {
        return thing.getStatus();
    }

    private ThingStatusDetail getDetail() {
        return thing.getStatusInfo().getStatusDetail();
    }

    private @Nullable String getDescription() {
        return thing.getStatusInfo().getDescription();
    }

    public void setCloudProvider(CloudProvider cloudProvider) {
        this.cloudProvider = cloudProvider;
    }

    public void setSecurity(Security security) {
        this.security = security;
    }

    /*
     * The {@link ConnectionManager} class is responsible for managing the state of the TCP connection to the
     * fan.
     *
     * @author Jacek Dobrowolski
     */
    private class ConnectionManager {
        private Logger logger = LoggerFactory.getLogger(ConnectionManager.class);

        private boolean deviceIsConnected;
        private boolean connectionIsAuthenticated;

        // private @Nullable InetAddress ifAddress;
        private @Nullable Socket socket;
        private @Nullable InputStream inputStream;
        private @Nullable DataOutputStream writer;
        // private final int SOCKET_CONNECT_TIMEOUT = 4000;

        private @Nullable ScheduledFuture<?> connectionMonitorJob;
        private final long CONNECTION_MONITOR_FREQ = 10L;
        private final long CONNECTION_MONITOR_DELAY = 10L;

        private @Nullable Response lastResponse;
        private final MideaACHandler mideaACHandler;

        @Nullable
        public Response getLastResponse() {
            return lastResponse;
        }

        Runnable connectionMonitorRunnable = () -> {
            logger.trace("Performing connection check for {} at IP {}", thing.getUID(), ipAddress);
            checkConnection();
        };

        public ConnectionManager(String ipv4Address, MideaACHandler mideaACHandler) {
            deviceIsConnected = false;
            this.mideaACHandler = mideaACHandler;
        }

        /*
         * Connect to the command and serial port(s) on the device. The serial connections are established only for
         * devices that support serial.
         */

        private Date getTokenReqested() {
            Cloud cloud = mideaACHandler.getClouds().get(getConfiguration().getEmail(),
                    getConfiguration().getPassword(), cloudProvider);
            return cloud.getTokenRequested();
        }

        private boolean reAuthenticationNeeded() {
            int reuth = getConfiguration().getReauth();
            if (reuth == 0) {
                return false;
            }
            Calendar now = Calendar.getInstance();
            Calendar tokenReqeustedAt = Calendar.getInstance();
            tokenReqeustedAt.setTime(getTokenReqested());
            tokenReqeustedAt.add(Calendar.HOUR, reuth);

            if (now.compareTo(tokenReqeustedAt) > 0) {
                return true;
            }
            return false;
        }

        protected synchronized void connect() {
            if (reAuthenticationNeeded()) {
                logger.info("Force re-authentication has initiated");
                authenticate();
            }
            if (isConnected()) {
                return;
            }
            logger.trace("Connecting to {} at {}:{}", thing.getUID(), ipAddress, ipPort);

            // Open socket
            try {
                socket = new Socket();
                socket.setSoTimeout(getConfiguration().getTimeout() * 1000);
                // socket.setReuseAddress(true);
                // socket.bind(new InetSocketAddress(0)); // TODO: allow choosing adapter? // new InetSocketAddress(0)
                // socket.setReuseAddress(true);
                if (ipPort != null) {
                    socket.connect(new InetSocketAddress(ipAddress, Integer.valueOf(ipPort)),
                            getConfiguration().getTimeout() * 1000);
                }
            } catch (IOException e) {
                logger.debug("IOException connecting to  {} at {}: {}", thing.getUID(), ipAddress, e.getMessage());
                String message = e.getMessage();
                if (message != null) {
                    markOfflineWithMessage(ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR, message);
                } else {
                    markOfflineWithMessage(ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR, "");
                }
                disconnect();
                scheduleConnectionMonitorJob();
                return;
            }

            // Create streams
            try {
                writer = new DataOutputStream(socket.getOutputStream());
                inputStream = socket.getInputStream();
            } catch (IOException e) {
                logger.warn("IOException getting streams for {} at {}: {}", thing.getUID(), ipAddress, e.getMessage(),
                        e);
                String message = e.getMessage();
                if (message != null) {
                    markOfflineWithMessage(ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR, message);
                } else {
                    markOfflineWithMessage(ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR, "");
                }
                disconnect();
                return;
            }
            logger.info("Connected to {} at {}", thing.getUID(), ipAddress);
            deviceIsConnected = true;
            markOnline();
            if (getVersion() != 3) {
                logger.debug("Device {}@{} not require authentication, getting status", thing.getUID(), ipAddress);
                requestStatus(true);
            } else {
                logger.debug("Device {}@{} require authentication, going to authenticate", thing.getUID(), ipAddress);
                authenticate();
            }
        }

        public void authenticate() {
            logger.trace("Version: {}", getVersion());
            logger.trace("Key: {}", getConfiguration().getKey());
            logger.trace("Token: {}", getConfiguration().getToken());

            if (getVersion() == 3) {
                if (StringUtils.isBlank(getConfiguration().getToken()) == false
                        && StringUtils.isBlank(getConfiguration().getKey()) == false) {
                    logger.debug("Device {}@{} authenticating", thing.getUID(), ipAddress);
                    doAuthentication();
                } else {
                    if (StringUtils.isBlank(getConfiguration().getToken())
                            && StringUtils.isBlank(getConfiguration().getKey())) {
                        if (StringUtils.isBlank(getConfiguration().getEmail())
                                || StringUtils.isBlank(getConfiguration().getPassword())) {
                            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                                    "Token and Key missing in configuration.");
                            logger.warn("Device {}@{} cannot authenticate, token and key missing", thing.getUID(),
                                    ipAddress);
                        } else {
                            if (StringUtils.isBlank(getConfiguration().getCloud())) {
                                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                                        "Cloud Provider missing in configuration.");
                                logger.warn("Device {}@{} cannot authenticate, Cloud Provider missing", thing.getUID(),
                                        ipAddress);
                            } else {
                                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_PENDING,
                                        "Retrieving Token and Key from cloud.");
                                logger.info("Retrieving Token and Key from cloud");
                                CloudProvider cloudProvider = CloudProvider
                                        .getCloudProvider(getConfiguration().getCloud());
                                getTokenKeyCloud(cloudProvider);
                            }
                        }
                    } else if (StringUtils.isBlank(getConfiguration().getToken())) {
                        updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                                "Token missing in configuration.");
                        logger.warn("Device {}@{} cannot authenticate, token missing", thing.getUID(), ipAddress);
                    } else if (StringUtils.isBlank(getConfiguration().getKey())) {
                        updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                                "Key missing in configuration.");
                        logger.warn("Device {}@{} cannot authenticate, key missing", thing.getUID(), ipAddress);
                    }
                }
            } else {
                logger.warn("Device {}@{} with version {} does not require authentication, not going to authenticate",
                        thing.getUID(), ipAddress, getVersion());
            }
        }

        private void getTokenKeyCloud(CloudProvider cloudProvider) {
            Cloud cloud = mideaACHandler.getClouds().get(getConfiguration().getEmail(),
                    getConfiguration().getPassword(), cloudProvider);
            // Cloud cloud = new Cloud(config.getEmail(), config.getPassword(), cloudProvider);
            cloud.setHttpClient(httpClient);
            if (cloud.login()) {
                TokenKey tk = cloud.getToken(getConfiguration().getDeviceId());
                Configuration configuration = editConfiguration();

                configuration.put(CONFIG_TOKEN, tk.getToken());
                configuration.put(CONFIG_KEY, tk.getKey());

                updateConfiguration(configuration);

                logger.trace("Token: {}", tk.getToken());
                logger.trace("Key: {}", tk.getKey());
                logger.warn("Token and Key obtained from cloud, saving, initializing");
                initialize();

            } else {
                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                        String.format("Can't retrieve Token and Key from Cloud (%s).", cloud.getErrMsg()));
                logger.warn("Can't retrieve Token and Key from Cloud ({})", cloud.getErrMsg());
            }
        }

        private void doAuthentication() {
            // byte[] request = Security.encode_8370(Utils.hexStringToByteArray(config.getToken()),
            // MsgType.MSGTYPE_HANDSHAKE_REQUEST);
            byte[] request = mideaACHandler.getSecurity().encode_8370(
                    Utils.hexStringToByteArray(getConfiguration().getToken()), MsgType.MSGTYPE_HANDSHAKE_REQUEST);
            try {
                logger.trace("Device {}@{} writing handshake_request: {}", thing.getUID(), ipAddress,
                        Utils.bytesToHex(request));
                write(request);
                byte[] response = read();
                logger.trace("Device {}@{} response for handshake_request length: {}", thing.getUID(), ipAddress,
                        response.length);
                if (response != null && response.length > 0) {
                    logger.trace("Device {}@{} response for handshake_request: {}", thing.getUID(), ipAddress,
                            Utils.bytesToHex(response));
                    if (response.length == 72) {
                        // boolean success = Security.tcp_key(Arrays.copyOfRange(response, 8, 72),
                        // Utils.hexStringToByteArray(config.getKey()));
                        boolean success = mideaACHandler.getSecurity().tcp_key(Arrays.copyOfRange(response, 8, 72),
                                Utils.hexStringToByteArray(getConfiguration().getKey()));
                        if (success) {
                            logger.debug("Authentication successufull");
                            connectionIsAuthenticated = true;
                            try {
                                Thread.sleep(1000);
                            } catch (InterruptedException e) {
                                logger.error("doAuthentication has thrown InterruptedException exception {}",
                                        e.getMessage());
                            }
                            requestStatus(true);
                        } else {
                            logger.debug("Invalid Key. Correct Key in configuration");
                            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                                    "Invalid Key. Correct Key in configuration.");
                        }
                    } else if ("ERROR".getBytes().equals(response)) {
                        logger.warn("Authentication failed!");
                    } else {
                        logger.warn("Authentication reponse unexpected data length ({} instead of 72)!",
                                response.length);
                        logger.debug("Invalid Token. Correct Token in configuration");
                        updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                                "Invalid Token. Correct Token in configuration.");
                    }

                }
            } catch (IOException e) {
                logger.error("doAuthentication has thrown IOException exception {}", e.getMessage());
            }
        }

        public void requestStatus(boolean restartMonitor) {
            CommandBase requestStatusCommand = new CommandBase();
            if (restartMonitor) {
                sendCommandAndMonitor(requestStatusCommand);
            } else {
                sendCommand(requestStatusCommand);
            }
        }

        public void sendCommandAndMonitor(CommandBase command) {
            cancelConnectionMonitorJob();
            sendCommand(command);
            scheduleConnectionMonitorJob();
        }

        public void sendCommand(CommandBase command) {
            if (command instanceof CommandSet) {
                ((CommandSet) command).setPromptTone(getConfiguration().getPromptTone());
            }
            Packet packet = new Packet(command, deviceId, mideaACHandler);
            packet.finalize();

            if (!isConnected()) {
                logger.debug("Unable to send message; no connection to {}. Trying to reconnect: {}", thing.getUID(),
                        command);
                connect();
                if (isConnected()) {
                    sendCommand(command);
                    return;
                }
            }

            try {
                byte[] bytes = packet.getBytes();
                logger.debug("Writing to {} at {} bytes.length: {}, bytes: {}", thing.getUID(), ipAddress, bytes.length,
                        Utils.bytesToHex(bytes));

                if (getVersion() == 3) {
                    bytes = mideaACHandler.getSecurity().encode_8370(bytes, MsgType.MSGTYPE_ENCRYPTED_REQUEST);
                }

                write(bytes);

                byte[] responseBytes = read();

                if (responseBytes != null) {
                    markOnline();

                    if (getVersion() == 3) {
                        Decryption8370Result result = mideaACHandler.getSecurity().decode_8370(responseBytes);
                        for (byte[] response : result.getResponses()) {
                            logger.debug("Response length: {}", response.length);
                            logger.trace("Packet: {}", Utils.bytesToHex(responseBytes));
                            if (response.length > 40 + 16) {
                                byte[] data = mideaACHandler.getSecurity()
                                        .aes_decrypt(Arrays.copyOfRange(response, 40, response.length - 16));
                                // The response data from the appliance includes a packet header which we don't want
                                data = Arrays.copyOfRange(data, 10, data.length);
                                logger.trace("Bytes decoded and stripped without header: length: {}, data: {}",
                                        data.length, Utils.bytesToHex(data));
                                if (data.length > 0) {
                                    if (data.length != 25) {
                                        logger.error("Response data is not 25 long!");
                                        return;
                                    }
                                    lastResponse = new Response(data, getVersion());
                                    try {
                                        processMessage(lastResponse);
                                    } catch (Exception ex) {
                                        logger.warn("Error processing response: {}", ex.getMessage());
                                    }
                                }
                            }
                        }
                    } else {
                        byte[] data = security
                                .aes_decrypt(Arrays.copyOfRange(responseBytes, 40, responseBytes.length - 16));
                        // The response data from the appliance includes a packet header which we don't want
                        data = Arrays.copyOfRange(data, 10, data.length);
                        logger.trace("Bytes decoded and stripped without header: length: {}, data: {}", data.length,
                                Utils.bytesToHex(data));

                        lastResponse = new Response(data, getVersion());
                        processMessage(lastResponse);
                    }
                    return;
                } else {
                    markOfflineWithMessage(ThingStatusDetail.COMMUNICATION_ERROR,
                            "Device not responding with its status.Response bytes is null.");
                }

            } catch (SocketException e) {
                logger.debug("SocketException writing to  {} at {}: {}", thing.getUID(), ipAddress, e.getMessage());
                String message = e.getMessage();
                if (message != null) {
                    markOfflineWithMessage(ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR, message);
                } else {
                    markOfflineWithMessage(ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR, "");
                }
                disconnect();
            } catch (IOException e) {
                logger.debug("IOException writing to  {} at {}: {}", thing.getUID(), ipAddress, e.getMessage());
                String message = e.getMessage();
                if (message != null) {
                    markOfflineWithMessage(ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR, message);
                } else {
                    markOfflineWithMessage(ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR, "");
                }
                disconnect();
            }
            scheduleConnectionMonitorJob();
        }

        protected synchronized void disconnect() {
            if (!isConnected()) {
                return;
            }
            logger.debug("Disconnecting from {} at {}", thing.getUID(), ipAddress);

            try {
                if (writer != null) {
                    writer.close();
                }
                if (inputStream != null) {
                    inputStream.close();
                }
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException e) {
                logger.warn("IOException closing connection to {} at {}: {}", thing.getUID(), ipAddress, e.getMessage(),
                        e);
            }
            deviceIsConnected = false;
            socket = null;
            inputStream = null;
            writer = null;
            markOffline();
        }

        private void updateChannel(String channelName, State state) {
            if (isOffline()) {
                return;
            }
            Channel channel = thing.getChannel(channelName);
            if (channel != null) {
                updateState(channel.getUID(), state);
            }
        }

        private void processMessage(Response response) {

            updateChannel(CHANNEL_POWER, response.getPowerState() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_IMODE_RESUME, response.getImmodeResume() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_TIMER_MODE, response.getTimerMode() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_APPLIANCE_ERROR, response.getApplianceError() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_TARGET_TEMPERATURE, new QuantityType<>(response.getTargetTemperature(),
                    response.getTempUnit() == true ? ImperialUnits.FAHRENHEIT : SIUnits.CELSIUS)); // new
                                                                                                   // DecimalType(response.getTargetTemperature()));
            updateChannel(CHANNEL_OPERATIONAL_MODE, new StringType(response.getOperationalMode().toString()));
            updateChannel(CHANNEL_FAN_SPEED, new StringType(response.getFanSpeed().toString()));
            updateChannel(CHANNEL_ON_TIMER, new StringType(response.getOnTimer().toChannel()));
            updateChannel(CHANNEL_OFF_TIMER, new StringType(response.getOffTimer().toChannel()));
            updateChannel(CHANNEL_SWING_MODE, new StringType(response.getSwingMode().toString()));
            updateChannel(CHANNEL_COZY_SLEEP, new DecimalType(response.getCozySleep()));
            updateChannel(CHANNEL_SAVE, response.getSave() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_LOW_FREQUENCY_FAN,
                    response.getLowFrequencyFan() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_SUPER_FAN, response.getSuperFan() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_FEEL_OWN, response.getFeelOwn() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_CHILD_SLEEP_MODE,
                    response.getChildSleepMode() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_EXCHANGE_AIR, response.getExchangeAir() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_DRY_CLEAN, response.getDryClean() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_AUX_HEAT, response.getAuxHeat() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_ECO_MODE, response.getEcoMode() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_CLEAN_UP, response.getCleanUp() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_TEMP_UNIT, response.getTempUnit() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_SLEEP_FUNCTION, response.getSleepFunction() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_TURBO_MODE, response.getTurboMode() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_CATCH_COLD, response.getCatchCold() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_NIGHT_LIGHT, response.getNightLight() == true ? OnOffType.ON : OnOffType.OFF);
            updateChannel(CHANNEL_PEAK_ELEC, response.getPeakElec() == true ? OnOffType.ON : OnOffType.OFF);

            updateChannel(CHANNEL_NATURAL_FAN, response.getNaturalFan() == true ? OnOffType.ON : OnOffType.OFF);

            float cit = dataHistory.get(CHANNEL_INDOOR_TEMPERATURE, response.getIndoorTemperature());
            updateChannel(CHANNEL_INDOOR_TEMPERATURE, new QuantityType<Temperature>(response.getIndoorTemperature(),
                    response.getTempUnit() == true ? ImperialUnits.FAHRENHEIT : SIUnits.CELSIUS)); // new
            // updateChannel(CHANNEL_INDOOR_TEMPERATURE, new
            // QuantityType<Temperature>(response.getIndoorTemperature(),response.getTempUnit() == true ?
            // ImperialUnits.FAHRENHEIT : SIUnits.CELSIUS)); // new
            // DecimalType(response.getIndoorTemperature()));
            updateChannel(CHANNEL_INDOOR_TEMPERATURE, new QuantityType<Temperature>(cit,
                    response.getTempUnit() == true ? ImperialUnits.FAHRENHEIT : SIUnits.CELSIUS));

            float cot = dataHistory.get(CHANNEL_OUTDOOR_TEMPERATURE, response.getOutdoorTemperature());
            // updateChannel(CHANNEL_OUTDOOR_TEMPERATURE, new
            // QuantityType<Temperature>(response.getOutdoorTemperature(), response.getTempUnit() == true ?
            // ImperialUnits.FAHRENHEIT : SIUnits.CELSIUS)); // new
            // DecimalType(response.getOutdoorTemperature()));
            updateChannel(CHANNEL_OUTDOOR_TEMPERATURE, new QuantityType<>(cot,
                    response.getTempUnit() == true ? ImperialUnits.FAHRENHEIT : SIUnits.CELSIUS));
            updateChannel(CHANNEL_HUMIDITY, new DecimalType(response.getHumidity()));
        }

        public byte @Nullable [] read() {
            byte[] bytes = new byte[512];
            try {
                if (inputStream != null) {
                    int len = inputStream.read(bytes);
                    if (len > 0) {
                        logger.debug("Response received length: {}", len);
                        bytes = Arrays.copyOfRange(bytes, 0, len);
                        logger.debug("Response bytes: {}", Utils.bytesToHex(bytes));
                        return bytes;
                    }
                }
            } catch (IOException e) {
                disconnect();
                String message = e.getMessage();
                if (message != null) {
                    markOfflineWithMessage(ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR, message);
                } else {
                    markOfflineWithMessage(ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR, "");
                }
            }

            return null;
        }

        public void write(byte[] buffer) throws IOException {
            if (writer == null) {
                logger.warn("fanWriter for {} is null when trying to write to {}!!!", thing.getUID(), ipAddress);
                return;
            }
            writer.write(buffer, 0, buffer.length);
        }

        private boolean isConnected() {
            return deviceIsConnected && !socket.isClosed() && socket.isConnected();
        }

        /*
         * Periodically validate the command connection to the device by executing a getversion command.
         */
        private void scheduleConnectionMonitorJob() {
            if (connectionMonitorJob == null) {
                logger.debug("Starting connection monitor job in {} seconds for {} at {}",
                        getConfiguration().getPollingTime(), thing.getUID(), ipAddress);
                connectionMonitorJob = scheduler.scheduleWithFixedDelay(connectionMonitorRunnable,
                        CONNECTION_MONITOR_DELAY, CONNECTION_MONITOR_FREQ, TimeUnit.SECONDS);
            }
        }

        private void cancelConnectionMonitorJob() {
            if (connectionMonitorJob != null) {
                logger.debug("Cancelling connection monitor job for {} at {}", thing.getUID(), ipAddress);
                connectionMonitorJob.cancel(true);
                connectionMonitorJob = null;
            }
        }

        private void checkConnection() {
            logger.trace("Checking status of connection for {} at {}", thing.getUID(), ipAddress);
            if (!isConnected()) {
                logger.debug("Connection check FAILED for {} at {}", thing.getUID(), ipAddress);
                if (getVersion() == 2 || getVersion() == 3 && connectionIsAuthenticated == true) {
                    connect();
                }
            } else {
                logger.debug("Connection check OK for {} at {}", thing.getUID(), ipAddress);
                logger.debug("Requesting status update from {} at {}", thing.getUID(), ipAddress);
                requestStatus(false);
            }
        }

        public void dispose() {
            cancelConnectionMonitorJob();
        }
    }
}
