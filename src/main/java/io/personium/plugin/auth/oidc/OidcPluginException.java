/**
 * personium.io
 * Copyright 2018 FUJITSU LIMITED
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.HttpStatus;

import io.personium.plugin.base.PluginException;
import io.personium.plugin.base.utils.EscapeControlCode;

/**
 * OidcPluginException.
 */
public class OidcPluginException extends PluginException {

    /** エラーメッセージ設定のキー. 後ろにメッセージコードをつけるのでドットまで定義. */
    private static final String ERROR_MESSAGE = "io.personium.core.msg.";
    /** エラーメッセージの設定を保持する. */
    private static final Properties ERR_MSG_PROP = loadProperties("personium-plugins-error-messages.properties");

    /** 必須パラメータが無い. */
    public static final OidcPluginException REQUIRED_PARAM_MISSING = create("PR400-AN-0016");
    /** IDTokenの検証の中で、受け取ったIdTokenのAudienceが信頼するClientIDのリストに無かった. */
    public static final OidcPluginException OIDC_WRONG_AUDIENCE = create("PR400-AN-0030");
    /** OIDCの認証エラー. */
    public static final OidcPluginException OIDC_AUTHN_FAILED = create("PR400-AN-0031");
    /** 無効なIDToken. */
    public static final OidcPluginException OIDC_INVALID_ID_TOKEN = create("PR400-AN-0032");
    /** IDTokenの有効期限切れ. */
    public static final OidcPluginException OIDC_EXPIRED_ID_TOKEN = create("PR400-AN-0033");
    /** 接続先が想定外の値を返却. */
    public static final OidcPluginException OIDC_UNEXPECTED_VALUE = create("PR400-AN-0034");
    /** 公開鍵の形式ｉ異常を返却. */
    public static final OidcPluginException OIDC_INVALID_KEY = create("PR400-AN-0035");

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
            throw new PluginException(HttpStatus.SC_INTERNAL_SERVER_ERROR, "Failed to load properties.");
        }
        return prop;
    }

    private OidcPluginException(int statusCode, String message) {
        super(statusCode, message);
    }

    /**
     * ファクトリーメソッド.
     * @param code メッセージコード
     * @return PluginException
     */
    public static OidcPluginException create(String code) {
        int statusCode = parseCode(code);
        String message = getMessage(code);
        return new OidcPluginException(statusCode, message);
    }

    /**
     * メッセージをパラメタ置換したものを作成して返します. エラーメッセージ上の $1 $2 等の表現がパラメタ置換用キーワードです。
     * @param params 付加メッセージ
     * @return PersoniumCoreMessage
     */
    public OidcPluginException params(Object... params) {
        // 置換メッセージ作成
        String ms = MessageFormat.format(getMessage(), params);
        // 制御コードのエスケープ処理
        ms = EscapeControlCode.escape(ms);
        // メッセージ置換クローンを作成
        return new OidcPluginException(getStatusCode(), ms);
    }

    /**
     * メッセージコードのパース.
     * @param code メッセージコード
     * @return ステータスコードまたはログメッセージの場合は-1。
     */
    private static int parseCode(String code) {
        Pattern p = Pattern.compile("^PR(\\d{3})-\\w{2}-\\d{4}$");
        Matcher m = p.matcher(code);
        if (!m.matches()) {
            throw new IllegalArgumentException(
                    "message code should be in \"PR000-OD-0000\" format. code=[" + code + "].");
        }
        return Integer.parseInt(m.group(1));
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
