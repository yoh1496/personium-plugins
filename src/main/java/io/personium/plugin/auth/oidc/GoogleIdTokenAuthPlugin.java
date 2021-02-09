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

import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

import io.personium.plugin.base.PluginConfig.OIDC;
import io.personium.plugin.base.PluginException;
import io.personium.plugin.base.PluginLog;
import io.personium.plugin.base.auth.AuthConst;
import io.personium.plugin.base.auth.AuthPlugin;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.AuthenticatedIdentity;

/**
 * GoogleIdTokenAuthPlugin.
 */
public class GoogleIdTokenAuthPlugin implements AuthPlugin {
    /** to String. **/
    public static final String PLUGIN_TOSTRING = "Google Open ID Connect Authentication";

    /** urn google grantType. **/
    public static final String PLUGIN_GRANT_TYPE = "urn:x-personium:oidc:google";
    /** Target account type. */
    private static final String PLUGIN_ACCOUNT_TYPE = "oidc:google";

    /** id token. */
    public static final String KEY_TOKEN = "id_token";

    /**
     * toString.
     * @return String
     */
    public String toString() {
        return PLUGIN_TOSTRING;
    }

    /**
     * getType.
     * @return String
     */
    @Override
    public String getType() {
        return AuthConst.PLUGIN_TYPE;
    }

    /**
     * getGrantType.
     * @return String
     */
    @Override
    public String getGrantType() {
        return PLUGIN_GRANT_TYPE;
    }

    /**
     * getAccountType.
     * @return String
     */
    @Override
    public String getAccountType() {
        return PLUGIN_ACCOUNT_TYPE;
    }

    /**
     * Google URL
     */
    /** Google URL scheme. */
    public static final String URL_HTTPS = "https://";
    /** Google URL host. */
    public static final String URL_ISSUER = "accounts.google.com";

    /**
     * Type値 oidc:google.
     */
    public static final String OIDC_PROVIDER = "google";

    /**
     * authenticate.
     * @param body body
     * @return au AuthenticatedIdentity
     * @throws AuthPluginException AuthPluginException
     */
    public AuthenticatedIdentity authenticate(Map<String, List<String>> body) throws AuthPluginException {
        AuthenticatedIdentity ai = null;
        if (body == null) {
            throw OidcPluginException.REQUIRED_PARAM_MISSING.create("Body");
        }

        // verify idToken
        String idToken = getSingleValue(body, KEY_TOKEN);

        GoogleIdToken ret = null;
        try {
            // id_tokenをパースする
            ret = GoogleIdToken.parse(idToken);
        } catch (PluginException pe) {
            throw OidcPluginException.INVALID_ID_TOKEN.create();
        }

        // Tokenの検証   検証失敗時にはPluginExceptionが投げられる
        ret.verify();

        String issuer = ret.getIssuer();
        String aud  = ret.getAudience();
        String mail = ret.getEmail();

        // Token検証成功の後処理
        // Googleが認めたissuerであるかどうか
        if (!issuer.equals(URL_ISSUER) && !issuer.equals(URL_HTTPS + URL_ISSUER)) {
            PluginLog.OIDC.INVALID_ISSUER.params(issuer).writeLog();
            throw OidcPluginException.AUTHN_FAILED.create();
        }

        // Googleに登録したサービス/アプリのClientIDかを確認
        // DcConfigPropatiesに登録したClientIdに一致していればOK
        if (!OIDC.isProviderClientIdTrusted(OIDC_PROVIDER, aud)) {
            throw OidcPluginException.WRONG_AUDIENCE.create(aud);
        }

        // 正常な場合、AuthenticatedIdentity を返却する。
        ai = new AuthenticatedIdentity();
        // アカウント名を設定する
        ai.setAccountName(mail);
        // アカウントタイプを設定する
        ai.setAccountType(AuthConst.KEY_OIDC_TYPE + ":" + OIDC_PROVIDER);

        return ai;
    }

    /**
     * Get single value in the body.
     * @param body request body
     * @param key map key
     * @return Value corresponding to key
     * @throws PluginException Value does not exist
     */
    private String getSingleValue(Map<String, List<String>> body, String key) throws AuthPluginException {
        List<String> valueList = body.get(key);
        if (valueList == null) {
            throw OidcPluginException.REQUIRED_PARAM_MISSING.create(key);
        }
        String value = valueList.get(0);
        if (StringUtils.isEmpty(value)) {
            throw OidcPluginException.REQUIRED_PARAM_MISSING.create(key);
        }
        return value;
    }
}
