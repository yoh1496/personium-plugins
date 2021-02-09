/**
 * Personium
 * Copyright 2017-2021 Personium Project Authors
 * - FUJITSU LIMITED
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.personium.plugin.auth.oidc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.personium.plugin.base.PluginException;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.AuthPluginUtils;
import io.personium.plugin.base.utils.PluginUtils;

/**
 * GoogleIdToken.
 */
public class GoogleIdToken {

    static Logger log = LoggerFactory.getLogger(GoogleIdToken.class);

    private String header;
    private String payload;
    private String signature;

    /* header */
    private String kid;

    /* payload */
    private String email;
    private String issuer;
    private String audience;
    private Long exp;

    private static final String GOOGLE_DISCOV_DOC_URL = "https://accounts.google.com/.well-known/openid-configuration";
    private static final String ALG = "SHA256withRSA";
    private static final String RSA = "RSA";
    private static final String KID = "kid";
    private static final String KTY = "kty";
    private static final String ISS = "iss";
    private static final String EML = "email";
    private static final String AUD = "aud";
    private static final String EXP = "exp";
    private static final String N = "n";
    private static final String E = "e";

    private static final int SPLIT_TOKEN_NUM = 3;
    private static final int VERIFY_WAIT = 60;
    private static final int VERIFY_SECOND = 1000;

    /**
     * GoogleIdToken.
     */
    public GoogleIdToken() {
    }

    /**
     * GoogleIdToken.
     * @param json JSON
     */
    public GoogleIdToken(JSONObject json) {
        this.setIssuer((String) json.get("issuer"));
        this.setEmail((String) json.get("email"));
        this.setAudience((String) json.get("audience"));
        this.setExp((Long) json.get("exp"));
    }

    /**
     * IdToken の検証のためのパース処理.
     *
     * @param idToken IDトークン
     *
     * @return googleIdToken GoogleIdToken
     * @throws AuthPluginException AuthPluginException
     */
    public static GoogleIdToken parse(String idToken) throws AuthPluginException {
        GoogleIdToken ret = new GoogleIdToken();

        String[] splitIdToken = idToken.split("\\.");
        if (splitIdToken.length != SPLIT_TOKEN_NUM) {
            throw OidcPluginException.INVALID_ID_TOKEN.create("2 periods required");
        }
        ret.header = splitIdToken[0];
        ret.payload = splitIdToken[1];
        ret.signature = splitIdToken[2];

        // TokenからJSONObjectを生成
        JSONObject header = null;
        JSONObject payload = null;
        try {
            header = (JSONObject) AuthPluginUtils.tokenToJSON(ret.header);
            payload = (JSONObject) AuthPluginUtils.tokenToJSON(ret.payload);
        } catch (ParseException e) {
            throw OidcPluginException.INVALID_ID_TOKEN.create("Header and payload should be Base64 encoded JSON.");
        }
        ret.kid = (String) header.get(KID);
        ret.issuer = (String) payload.get(ISS);
        ret.email = (String) payload.get(EML);
        ret.audience = (String) payload.get(AUD);
        ret.exp = (Long) payload.get(EXP);

        return ret;
    }

    /**
     * Verification signature.
     * @throws AuthPluginException AuthPluginException
     */
    public void verify() throws AuthPluginException {
        // 有効期限
        isExpired(this.getExp());

        RSAPublicKey rsaPubKey = this.getKey();
        try {
            Signature sig = Signature.getInstance(ALG);
            sig.initVerify(rsaPubKey);
            sig.update((this.getHeader() + "." + this.getPayload()).getBytes());
            boolean verified = sig.verify(PluginUtils.decodeBase64Url(this.getSignature()));
            if (!verified) {
                // 署名検証結果、署名が不正であると認定
                throw OidcPluginException.AUTHN_FAILED.create();
            }

        } catch (NoSuchAlgorithmException e) {
            // 環境がおかしい以外でここには来ない
            throw OidcPluginException.UNEXPECTED_VALUE.create(ALG + " not supported.");

        } catch (InvalidKeyException e) {
            // バグ以外でここには来ない
            throw OidcPluginException.INVALID_KEY.create(ALG + " not supported.");

        } catch (SignatureException e) {
            // IdTokenのSignatureがおかしい
            // the passed-in signature is improperly encoded or of the wrong
            // type,
            // if this signature algorithm is unable to process the input data
            // provided, etc.
            throw OidcPluginException.INVALID_ID_TOKEN.create("ID Token sig value is invalid");
        }
    }

    /**
     * getJwksUri.
     * @param endpoint
     * @return
     * @throws PluginException
     */
    private static String getJwksUri(String endpoint) throws AuthPluginException {
        try {
            return (String) PluginUtils.getHttpJSON(endpoint).get("jwks_uri");
        } catch (ClientProtocolException e) {
            // HTTPのプロトコル違反
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(endpoint, "proper HTTP response");
        } catch (IOException e) {
            // サーバーに接続できない場合に発生
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(HttpGet.METHOD_NAME, endpoint, "");
        } catch (ParseException e) {
            // JSONでないものを返してきた
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(endpoint, "JSON");
        }
    }

    /**
     * getKeys.
     * @param url String
     * @return JSONArray
     * @throws PluginException
     */
    private static JSONArray getKeys() throws AuthPluginException {
        String endpoint = getJwksUri(GOOGLE_DISCOV_DOC_URL);
        try {
            return (JSONArray) PluginUtils.getHttpJSON(endpoint).get("keys");
        } catch (ClientProtocolException e) {
            // HTTPのプロトコル違反
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(endpoint, "proper HTTP response");
        } catch (IOException e) {
            // サーバーに接続できない場合に発生
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(HttpGet.METHOD_NAME, endpoint, "");
        } catch (ParseException e) {
            // JSONでないものを返してきた
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(endpoint, "JSON");
        }
    }

    /**
     * 公開鍵情報から、IDTokenのkidにマッチする方で公開鍵を生成.
     *
     * @return RSAPublicKey 公開鍵
     * @throws PluginException
     */
    private RSAPublicKey getKey() throws AuthPluginException {
        JSONArray jsonAry;
        jsonAry = getKeys();
        for (int i = 0; i < jsonAry.size(); i++) {
            JSONObject k = (JSONObject) jsonAry.get(i);
            String compKid = (String) k.get(KID);
            if (compKid.equals(this.getKid())) {
                BigInteger n = new BigInteger(1, PluginUtils.decodeBase64Url((String) k.get(N)));
                BigInteger e = new BigInteger(1, PluginUtils.decodeBase64Url((String) k.get(E)));
                RSAPublicKeySpec rsaPubKey = new RSAPublicKeySpec(n, e);
                try {
                    KeyFactory kf = KeyFactory.getInstance((String) k.get(KTY));
                    return (RSAPublicKey) kf.generatePublic(rsaPubKey);

                } catch (NoSuchAlgorithmException e1) {
                    // ktyの値がRSA以外はサポートしない
                    throw OidcPluginException.UNEXPECTED_VALUE.create(KTY, RSA);

                } catch (InvalidKeySpecException e1) {
                    // バグ以外でここには来ない
                    throw OidcPluginException.INVALID_KEY.create(KTY, RSA);
                }
            }
        }
        // 該当するkidを持つ鍵情報が取れなかった場合
        throw OidcPluginException.INVALID_ID_TOKEN.create("ID Token header value is invalid.");
    }

    /**
     * isExpired.
     * @throws PluginException
     */
    private void isExpired(Long expLong) throws AuthPluginException {
        // exp で Token の有効期限が切れているか確認
        // Tokenに有効期限(exp)があるかnullチェック
        if (expLong == null) {
            throw OidcPluginException.INVALID_ID_TOKEN.create("ID Token expiration time null.");
        }

        // expireしていないかチェック(60秒くらいは過ぎても良い)
        boolean expired = (expLong + VERIFY_WAIT) * VERIFY_SECOND < System.currentTimeMillis();
        if (expired) {
            throw OidcPluginException.EXPIRED_ID_TOKEN.create("This ID Token has expired. EXP=" + expLong);
        }
    }

    /**
     * getHeader.
     * @return header
     */
    public String getHeader() {
        return header;
    }

    /**
     * setHeader.
     * @param header HEADER
     */
    public void setHeader(String header) {
        this.header = header;
    }

    /**
     * getPayload.
     * @return payload
     */
    public String getPayload() {
        return payload;
    }

    /**
     * setPayload.
     * @param payload PAYLOAD
     */
    public void setPayload(String payload) {
        this.payload = payload;
    }

    /**
     * getSignature.
     * @return signature
     */
    public String getSignature() {
        return signature;
    }

    /**
     * setSignature.
     * @param signature SIGATURE
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * getKid.
     * @return kid
     */
    public String getKid() {
        return kid;
    }

    /**
     * setKid.
     * @param kid KID
     */
    public void setKid(String kid) {
        this.kid = kid;
    }

    /**
     * getEmail.
     * @return email
     */
    public String getEmail() {
        return email;
    }

    /**
     * setEmail.
     * @param email E-MAIL
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * getIssuer.
     * @return issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * setIssuer.
     * @param issuer ISSUER
     */
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * getAudience.
     * @return audience
     */
    public String getAudience() {
        return audience;
    }

    /**
     * setAudience.
     * @param audience audience
     */
    public void setAudience(String audience) {
        this.audience = audience;
    }

    /**
     * getExp.
     * @return exp
     */
    public Long getExp() {
        return exp;
    }

    /**
     * setExp.
     * @param exp exp
     */
    public void setExp(Long exp) {
        this.exp = exp;
    }
}
