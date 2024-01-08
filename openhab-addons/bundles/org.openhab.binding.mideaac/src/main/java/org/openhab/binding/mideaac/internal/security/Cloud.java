package org.openhab.binding.mideaac.internal.security;

import java.nio.ByteOrder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.util.StringContentProvider;
import org.eclipse.jetty.http.HttpMethod;
import org.openhab.binding.mideaac.internal.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class Cloud {
    private final Logger logger = LoggerFactory.getLogger(Cloud.class);

    private static final Gson GSON = new Gson();

    // private static final String SERVER_URL = "https://mp-prod.appsmb.com/mas/v5/app/proxy?alias=";

    private static final int CLIENT_TYPE = 1; // Android
    private static final int FORMAT = 2; // JSON
    private static final String LANGUAGE = "en_US";
    // private static final String APP_ID = "1010";
    // private static final String SRC = "1010";

    private Date tokenRequestedAt = new Date();

    private void setTokenRequested() {
        tokenRequestedAt = new Date();
    }

    public Date getTokenRequested() {
        return tokenRequestedAt;
    }

    private @Nullable HttpClient httpClient;

    public HttpClient getHttpClient() {
        return httpClient;
    }

    public void setHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    private String errMsg;

    public String getErrMsg() {
        return errMsg;
    }

    private @Nullable String accessToken = "";

    private String loginAccount;
    private String password;
    private CloudProvider cloudProvider;
    private Security security;

    private @Nullable String loginId;
    private @Nullable String sessionId;

    public Cloud(String email, String password, CloudProvider cloudProvider) {
        this.loginAccount = email;
        this.password = password;
        this.cloudProvider = cloudProvider;
        this.security = new Security(cloudProvider);
        logger.debug("Cloud provider: {}", cloudProvider.getName());
    }

    private JsonObject apiRequest(String endpoint, JsonObject args, JsonObject data) {
        // Set up the initial data payload with the global variable set
        if (data == null) {
            data = new JsonObject();
            data.addProperty("appId", cloudProvider.getAppId());
            data.addProperty("format", FORMAT);
            data.addProperty("clientType", CLIENT_TYPE);
            data.addProperty("language", LANGUAGE);
            data.addProperty("src", cloudProvider.getSrc());
            data.addProperty("stamp", new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()));
        }

        // Add the method parameters for the endpoint
        if (args != null) {
            for (Map.Entry<String, JsonElement> entry : args.entrySet()) {
                data.add(entry.getKey(), entry.getValue().getAsJsonPrimitive());
            }
        }

        // Add the login information to the payload

        if (data.has("reqId") == false && !StringUtils.isBlank(cloudProvider.getProxied())) {
            data.addProperty("reqId", Utils.token_hex(16));
        }

        String url = cloudProvider.getApiUrl() + endpoint;

        int time = (int) (new Date().getTime() / 1000);

        String random = String.valueOf(time);

        // Add the sign to the header

        String json = data.toString();
        logger.debug("Request json: {}", json);

        Request request = httpClient.newRequest(url).method(HttpMethod.POST).timeout(15, TimeUnit.SECONDS);

        // .version(HttpVersion.HTTP_1_1)
        request.agent("Dalvik/2.1.0 (Linux; U; Android 7.0; SM-G935F Build/NRD90M)");

        if (!StringUtils.isBlank(cloudProvider.getProxied())) {
            request.header("Content-Type", "application/json");
        } else {
            request.header("Content-Type", "application/x-www-form-urlencoded");
        }
        request.header("secretVersion", "1");
        if (!StringUtils.isBlank(cloudProvider.getProxied())) {
            String sign = security.new_sign(json, random);
            request.header("sign", sign);
        } else {
            if (!StringUtils.isBlank(sessionId)) {
                data.addProperty("sessionId", sessionId);
            }
            String sign = security.sign(url, data);
            data.addProperty("sign", sign);
            request.header("sign", sign);
        }

        request.header("random", random);
        request.header("accessToken", accessToken);

        logger.debug("Request headers: {}", request.getHeaders().toString());

        if (!StringUtils.isBlank(cloudProvider.getProxied())) {
            request.content(new StringContentProvider(json));
        } else {
            String body = Utils.getQueryString(data);
            logger.debug("Request body: {}", body);
            request.content(new StringContentProvider(body));
        }

        // POST the endpoint with the payload
        ContentResponse cr = null;
        try {
            cr = request.send();
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (TimeoutException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ExecutionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        if (cr != null) {
            logger.debug("Response json: {}", cr.getContentAsString());
            JsonObject result = new Gson().fromJson(cr.getContentAsString(), JsonObject.class);

            int code = -1;

            if (result.get("errorCode") != null) {
                code = result.get("errorCode").getAsInt();
            } else if (result.get("code") != null) {
                code = result.get("code").getAsInt();
            } else {
                errMsg = "No code in cloud response";
                logger.warn("Error logging to Cloud: {}", errMsg);
                return null;
            }

            String msg = result.get("msg").getAsString();
            if (code != 0) {
                errMsg = msg;
                handle_api_error(code, msg);
                logger.warn("Error logging to Cloud: {}", msg);
                return null;
            } else {
                logger.debug("Api response ok: {} ({})", code, msg);
                if (!StringUtils.isBlank(cloudProvider.getProxied())) {
                    return result.get("data").getAsJsonObject();
                } else {
                    return result.get("result").getAsJsonObject();
                }
            }
        } else {
            logger.warn("No response from cloud!");
        }

        return null;
    }

    // Performs a user login with the credentials supplied to the constructor
    public boolean login() {
        if (loginId == null) {
            if (getLoginId() == false) {
                return false;
            }
        }
        // Don't try logging in again, someone beat this thread to it
        if (!StringUtils.isBlank(sessionId)) {
            return true;
        }

        logger.trace("Using loginId: {}", loginId);
        logger.trace("Using password: {}", password);

        if (!StringUtils.isBlank(cloudProvider.getProxied())) {
            JsonObject _data = new JsonObject();

            JsonObject data = new JsonObject();
            data.addProperty("platform", FORMAT);
            _data.add("data", data);

            JsonObject iotData = new JsonObject();
            iotData.addProperty("appId", cloudProvider.getAppId());
            iotData.addProperty("clientType", CLIENT_TYPE);
            iotData.addProperty("iampwd", security.encrypt_iam_password(loginId, password));
            iotData.addProperty("loginAccount", loginAccount);
            iotData.addProperty("password", security.encryptPassword(loginId, password));
            iotData.addProperty("pushToken", Utils.token_urlsafe(120));
            iotData.addProperty("reqId", Utils.token_hex(16));
            iotData.addProperty("src", cloudProvider.getSrc());
            iotData.addProperty("stamp", new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()));
            _data.add("iotData", iotData);

            JsonObject response = apiRequest("/mj/user/login", null, _data);

            if (response == null) {
                return false;
            }

            accessToken = response.getAsJsonObject("mdata").get("accessToken").getAsString();
        } else {
            String passwordEncrypted = security.encryptPassword(loginId, password);

            JsonObject data = new JsonObject();
            data.addProperty("loginAccount", loginAccount);
            data.addProperty("password", passwordEncrypted);

            JsonObject response = apiRequest("/v1/user/login", data, null);

            if (response == null) {
                return false;
            }

            accessToken = response.get("accessToken").getAsString();
            sessionId = response.get("sessionId").getAsString();

        }

        return true;
    }

    // Get tokenlist with udpid
    public TokenKey getToken(String udpid) {
        long i = Long.valueOf(udpid);

        // if (!StringUtils.isBlank(cloudProvider.getProxied())) {
        JsonObject args = new JsonObject();
        args.addProperty("udpid", security.getUdpId(Utils.toIntTo6ByteArray(i, ByteOrder.BIG_ENDIAN)));
        JsonObject response = apiRequest("/v1/iot/secure/getToken", args, null);

        if (response == null) {
            return null;
        }

        // logger.trace("response: {}", response.toString());
        // JsonObject data = response.getAsJsonObject("data");
        // logger.trace("data: {}", data.toString());

        JsonArray tokenlist = response.getAsJsonArray("tokenlist");
        JsonObject el = tokenlist.get(0).getAsJsonObject();
        String token = el.getAsJsonPrimitive("token").getAsString();
        String key = el.getAsJsonPrimitive("key").getAsString();

        setTokenRequested();

        return new TokenKey(token, key);
        // } else {
        // JsonObject response = apiRequest("/v1/appliance/user/list/get", null, null);
        //
        // if (response == null) {
        // return null;
        // }
        //
        // logger.trace("response: {}", response.toString());
        // // JsonObject data = response.getAsJsonObject("data");
        // // logger.trace("data: {}", data.toString());
        // String token = "";
        // String key = "";
        // return new TokenKey(token, key);
        // }
    }

    // Get the login ID from the email address
    private boolean getLoginId() {
        JsonObject args = new JsonObject();
        args.addProperty("loginAccount", loginAccount);
        JsonObject response = apiRequest("/v1/user/login/id/get", args, null);
        if (response == null) {
            return false;
        }
        loginId = response.get("loginId").getAsString();
        return true;
    }

    private void handle_api_error(int asInt, @NonNull String asString) {
        // TODO Auto-generated method stub
    }
}
