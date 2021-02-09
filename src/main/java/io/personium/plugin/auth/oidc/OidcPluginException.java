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
import java.io.InputStream;
import java.text.MessageFormat;
import java.util.Properties;

import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.OAuth2Helper;
import io.personium.plugin.base.utils.EscapeControlCode;

/**
 * OidcPluginException.
 */
public class OidcPluginException {

    /** エラーメッセージ設定のキー. 後ろにメッセージコードをつけるのでドットまで定義. */
    private static final String ERROR_MESSAGE = "io.personium.core.msg.";
    /** エラーメッセージの設定を保持する. */
    private static final Properties ERR_MSG_PROP = loadProperties("personium-plugins-error-messages.properties");

    /** 必須パラメータが無い. */
    public static final OidcPluginException REQUIRED_PARAM_MISSING =
            new OidcPluginException(OAuth2Helper.Error.INVALID_REQUEST, "PR400-AN-0001");
    /** IDTokenの検証の中で、受け取ったIdTokenのAudienceが信頼するClientIDのリストに無かった. */
    public static final OidcPluginException WRONG_AUDIENCE =
            new OidcPluginException(OAuth2Helper.Error.INVALID_GRANT, "PR400-AN-0002");
    /** OIDCの認証エラー. */
    public static final OidcPluginException AUTHN_FAILED =
            new OidcPluginException(OAuth2Helper.Error.INVALID_GRANT, "PR400-AN-0003");
    /** 無効なIDToken. */
    public static final OidcPluginException INVALID_ID_TOKEN =
            new OidcPluginException(OAuth2Helper.Error.INVALID_GRANT, "PR400-AN-0004");
    /** IDTokenの有効期限切れ. */
    public static final OidcPluginException EXPIRED_ID_TOKEN =
            new OidcPluginException(OAuth2Helper.Error.INVALID_GRANT, "PR400-AN-0005");
    /** 接続先が想定外の値を返却. */
    public static final OidcPluginException UNEXPECTED_VALUE =
            new OidcPluginException(OAuth2Helper.Error.INVALID_GRANT, "PR400-AN-0006");
    /** 公開鍵の形式ｉ異常を返却. */
    public static final OidcPluginException INVALID_KEY =
            new OidcPluginException(OAuth2Helper.Error.INVALID_GRANT, "PR400-AN-0007");

    /**  HTTPリクエストに失敗. */
    public static final OidcPluginException HTTP_REQUEST_FAILED =
            new OidcPluginException(OAuth2Helper.Error.SERVER_ERROR, "PR500-NW-0001");
    /** 接続先が想定外の応答を返却. */
    public static final OidcPluginException UNEXPECTED_RESPONSE =
            new OidcPluginException(OAuth2Helper.Error.SERVER_ERROR, "PR500-NW-0002");

    /** OAuth2.0 response "error". */
    private String oAuth2Error;
    /** Response message. */
    private String message;

    /**
     * Load properties file.
     * @param file Properties file
     * @return Properties file object
     */
    private static Properties loadProperties(String file) {
        Properties prop = new Properties();
        prop.clear();
        try (InputStream is = OidcPluginException.class.getClassLoader().getResourceAsStream(file)) {
            prop.load(is);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load properties.", e);
        }
        return prop;
    }

    /**
     * Constructor.
     * @param oAuth2Error OAuth2.0 response "error"
     * @param messageCode Response message code
     */
    private OidcPluginException(String oAuth2Error, String messageCode) {
        this.oAuth2Error = oAuth2Error;
        message = getMessage(messageCode);
    }

    /**
     * Create AuthPluginException.
     * @return AuthPluginException
     */
    public AuthPluginException create() {
        switch (oAuth2Error) {
            case OAuth2Helper.Error.INVALID_REQUEST:
                return new AuthPluginException.InvalidRequest(message);
            case OAuth2Helper.Error.INVALID_CLIENT:
                return new AuthPluginException.InvalidClient(message);
            case OAuth2Helper.Error.INVALID_GRANT:
                return new AuthPluginException.InvalidGrant(message);
            case OAuth2Helper.Error.UNAUTHORIZED_CLIENT:
                return new AuthPluginException.UnauthorizedClient(message);
            case OAuth2Helper.Error.ACCESS_DENIED:
                return new AuthPluginException.AccessDenied(message);
            case OAuth2Helper.Error.UNSUPPORTED_GRANT_TYPE:
                return new AuthPluginException.UnsupportedGrantType(message);
            case OAuth2Helper.Error.UNSUPPORTED_RESPONSE_TYPE:
                return new AuthPluginException.UnsupportedResponseType(message);
            case OAuth2Helper.Error.INVALID_SCOPE:
                return new AuthPluginException.InvalidScope(message);
            case OAuth2Helper.Error.SERVER_ERROR:
                return new AuthPluginException.ServerError(message);
            case OAuth2Helper.Error.TEMPORARILY_UNAVAILABLE:
                return new AuthPluginException.TemporarilyUnavailable(message);
            default:
                throw new RuntimeException("Exception settings error.");
        }
    }

    /**
     * Create AuthPluginException.
     * @param messageParams message parameters
     * @return AuthPluginException
     */
    public AuthPluginException create(Object... messageParams) {
        String ms = MessageFormat.format(message, messageParams);
        message = EscapeControlCode.escape(ms);
        return create();
    }

    /**
     * 設定ファイルからメッセージの取得.
     * @param code メッセージコード
     * @return メッセージ
     */
    private static String getMessage(String code) {
        String msg = ERR_MSG_PROP.getProperty(ERROR_MESSAGE + code);
        if (msg == null) {
            // ログが定義されていなかったら例外
            throw new RuntimeException("message undefined for code=[" + code + "].");
        }
        return msg;
    }
}
