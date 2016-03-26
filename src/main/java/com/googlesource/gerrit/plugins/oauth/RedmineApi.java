package com.googlesource.gerrit.plugins.oauth;

import static org.scribe.utils.OAuthEncoder.encode;

import com.google.common.io.BaseEncoding;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.model.OAuthConstants;
import org.scribe.oauth.OAuthService;

import static com.google.gerrit.server.OutputFormat.JSON;
import static java.lang.String.format;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static org.scribe.model.OAuthConstants.ACCESS_TOKEN;
import static org.scribe.model.OAuthConstants.CODE;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.slf4j.LoggerFactory.getLogger;

public class RedmineApi extends DefaultApi20 {
	private static final Logger log = getLogger(RedmineApi.class);
	private static final String AUTHORIZE_URL =
		"http://192.168.1.10/redmine_2/oauth2/authorize_client?response_type=code&client_id=%s&redirect_uri=%s";
	private static final String ACCESS_TOKEN_ENDPOINT =
		"http://192.168.1.10/redmine_2/oauth2/verify_access";

	public RedmineApi() {
	}

	@Override
		public String getAuthorizationUrl(OAuthConfig config) {
			return format(AUTHORIZE_URL, config.getApiKey(), encode(config.getCallback()));
		}

	@Override
		public String getAccessTokenEndpoint() {
			return ACCESS_TOKEN_ENDPOINT;
		}
/*
	@Override
		public OAuthService createService(OAuthConfig config) {
			log.info("create service");
			return new RedmineOAuthService(this, config);
		}

	@Override
		public AccessTokenExtractor getAccessTokenExtractor() {
			return new RedmineTokenExtractor();
		}

	private static final class RedmineOAuthService implements OAuthService {
		private static final String VERSION = "2.0";

		private static final String GRANT_TYPE = "grant_type";
		private static final String GRANT_TYPE_VALUE = "authorization_code";

		private final DefaultApi20 api;
		private final OAuthConfig config;

		private RedmineOAuthService(DefaultApi20 api, OAuthConfig config) {
			this.config = config;
			this.api = api;
		}

		@Override
			public Token getAccessToken(Token token, Verifier verifier) {
				log.info("get access token");
				OAuthRequest request =
					new OAuthRequest(api.getAccessTokenVerb(),
							api.getAccessTokenEndpoint());
				request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
				request.addBodyParameter(OAuthConstants.CLIENT_SECRET,
						config.getApiSecret());
				request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
				request.addBodyParameter(OAuthConstants.REDIRECT_URI,
						config.getCallback());
				if (config.hasScope())
					request.addBodyParameter(OAuthConstants.SCOPE, config.getScope());
				request.addBodyParameter(GRANT_TYPE, GRANT_TYPE_VALUE);
				Response response = request.send();
				return api.getAccessTokenExtractor().extract(response.getBody());
			}

		@Override
			public Token getRequestToken() {
				log.info("get request token");
				throw new UnsupportedOperationException(
						"Unsupported operation, please use 'getAuthorizationUrl' and redirect your users there");
			}

		@Override
			public String getVersion() {
				return VERSION;
			}


		@Override
			public String getAuthorizationUrl(Token requestToken) {
				return api.getAuthorizationUrl(config);
			}

		@Override
			public void signRequest(Token accessToken, OAuthRequest request) {
				request.addQuerystringParameter(OAuthConstants.ACCESS_TOKEN,
						accessToken.getToken());
			}
	}

	private static final class RedmineTokenExtractor implements AccessTokenExtractor {
		private static final Logger log = getLogger(RedmineTokenExtractor.class);

		@Override
			public Token extract(String response) {
				log.info("access token extract");
				return new Token("", "");
			}
	}
	*/
}

