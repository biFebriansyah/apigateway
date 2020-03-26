package com.finaltest.apigateway.service;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import okhttp3.Request;
import okhttp3.*;

import java.io.IOException;
import java.util.ArrayList;

@Service
public class userDetailService implements UserDetailsService {

    @Value("${base.AurhUrl}")
    String baseUrl;

    private final OkHttpClient httpClient = new OkHttpClient();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            Request req = new Request.Builder()
                    .url(baseUrl + "/users?email=" + username)
                    .build();
            Response res = httpClient.newCall(req).execute();
            String respone = res.body().string();
            JSONObject data = new JSONObject(respone);
            return new User(data.get("email").toString(), data.get("password").toString(), new ArrayList<>());

        } catch (IOException err) {
            return null;
        } catch (JSONException jnerr) {
            return null;
        }
    }
}
