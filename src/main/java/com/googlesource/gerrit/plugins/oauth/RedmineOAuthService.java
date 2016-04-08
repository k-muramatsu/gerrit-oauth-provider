package com.googlesource.gerrit.plugins.oauth;

import com.google.common.base.CharMatcher;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.gerrit.extensions.annotations.PluginName;
import com.google.gerrit.extensions.auth.oauth.OAuthServiceProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthToken;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.gerrit.extensions.auth.oauth.OAuthVerifier;
import com.google.gerrit.server.OutputFormat;
import com.google.gerrit.server.config.CanonicalWebUrl;
import com.google.gerrit.server.config.PluginConfig;
import com.google.gerrit.server.config.PluginConfigFactory;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;

import org.apache.commons.codec.binary.Base64;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static com.google.gerrit.server.OutputFormat.JSON;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static org.slf4j.LoggerFactory.getLogger;
import static java.lang.String.format;

@Singleton
class RedmineOAuthService implements OAuthServiceProvider {
	private static final Logger log = getLogger(RedmineOAuthService.class);
	static final String CONFIG_SUFFIX = "-redmine-oauth";
	private static final String PROTECTED_RESOURCE_URL =
	      "%s/oauth2/user";
	private final OAuthService service;
	private final String canonicalWebUrl;
	private final String base_url;

	@Inject
		RedmineOAuthService(PluginConfigFactory cfgFactory,
				@PluginName String pluginName,
				@CanonicalWebUrl Provider<String> urlProvider) {
			PluginConfig cfg = cfgFactory.getFromGerritConfig(
			        pluginName + CONFIG_SUFFIX);
			this.canonicalWebUrl = CharMatcher.is('/').trimTrailingFrom(
			        urlProvider.get()) + "/";
			base_url = CharMatcher.is('/').trimTrailingFrom(cfg.getString(InitOAuth.BASE_URL));

			service = new ServiceBuilder().provider(new RedmineApi(base_url))
				.apiKey(cfg.getString(InitOAuth.CLIENT_ID))
				.apiSecret(cfg.getString(InitOAuth.CLIENT_SECRET))
				.callback(this.canonicalWebUrl + "oauth")
				.build();
		
	}

	private String getProtectedResourceUrl() {
		return format(PROTECTED_RESOURCE_URL, base_url);
	}

	@Override
		public OAuthUserInfo getUserInfo(OAuthToken token) throws IOException {
			OAuthRequest request = new OAuthRequest(Verb.GET, getProtectedResourceUrl());
			Token t = new Token(token.getToken(), token.getSecret(), token.getRaw());
			service.signRequest(t, request);
			Response response = request.send();
			if (response.getCode() != SC_OK) {
				throw new IOException(String.format("Status %s (%s) for request %s",
							response.getCode(), response.getBody(), request.getUrl()));
			}
			JsonElement userJson =
				JSON.newGson().fromJson(response.getBody(), JsonElement.class);
			if (log.isDebugEnabled()) {
				log.debug("User info response: {}", response.getBody());
			}
			if (userJson.isJsonObject()) {
				JsonObject jsonObject = userJson.getAsJsonObject();
				JsonObject userObject = jsonObject.getAsJsonObject("user");
				if (userObject == null || userObject.isJsonNull()) {
					throw new IOException("Response doesn't contain 'user' field");
				}
				JsonElement usernameElement = userObject.get("id");
				String username = usernameElement.getAsString();

				JsonElement displayName = userObject.get("login");
				String disp_name = userObject.get("firstname") + " " + userObject.get("lastname");
				return new OAuthUserInfo(
							username, 
							displayName.getAsString(), 
							userObject.get("mail").getAsString(),
							disp_name,
							null);
			} else {
				throw new IOException(
						String.format("Invalid JSON '%s': not a JSON Object", userJson));
			}
		}

	@Override
		public OAuthToken getAccessToken(OAuthVerifier rv) {
			Verifier vi = new Verifier(rv.getValue());
			Token to = service.getAccessToken(null, vi);
			return new OAuthToken(to.getToken(), to.getSecret(), null);
		}

	@Override
		public String getAuthorizationUrl() {
			return service.getAuthorizationUrl(null);
		}

	@Override
		public String getVersion() {
			return service.getVersion();
		}

	@Override
		public String getName() {
			return "Redmine OAuth2";
		}
}
