/*
 * *
 *  * Copyright 2019 eBay Inc.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *  http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *  *
 */

using System;
using Xunit;
using System.Collections.Generic;
using eBay.ApiClient.Auth.OAuth2.Model;
using System.IO;
using OpenQA.Selenium;
using System.Threading;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Firefox;
using System.Collections.Specialized;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Web;

namespace eBay.ApiClient.Auth.OAuth2
{
    public class OAuth2ApiTest : IDisposable
    {
        private OAuth2Api oAuth2Api = new OAuth2Api();
        private readonly IList<string> scopes = new List<string>()
            {
                "https://api.ebay.com/oauth/api_scope/buy.marketing",
                "https://api.ebay.com/oauth/api_scope"
            };

        private readonly IList<string> userScopes = new List<string>()
            {
                "https://api.ebay.com/oauth/api_scope/commerce.catalog.readonly",
                "https://api.ebay.com/oauth/api_scope/buy.shopping.cart"
            };

        public OAuth2ApiTest()
        {
            LoadCredentials();
        }

        public void Dispose()
        {
            // clean up test data here
        }

        [Fact]
        public void GetApplicationToken_Production_Success()
        {
            GetApplicationToken_Success(OAuthEnvironment.PRODUCTION);
        }

        [Fact]
        public void GetApplicationToken_Sandbox_Success()
        {
            GetApplicationToken_Success(OAuthEnvironment.SANDBOX);
        }

        [Fact]
        public void GetApplicationToken_ProductionCache_Success()
        {
            GetApplicationToken_Success(OAuthEnvironment.PRODUCTION);
        }

        [Fact]
        public void GetApplicationToken_SandboxCache_Success()
        {
            GetApplicationToken_Success(OAuthEnvironment.SANDBOX);
        }

        [Fact]
        public void GetApplicationToken_NullEnvironment_Failure()
        {
            Assert.Throws<ArgumentException>(() => oAuth2Api.GetApplicationToken(null, scopes));
        }

        [Fact]
        public void GetApplicationToken_NullScopes_Failure()
        {
            Assert.Throws<ArgumentException>(() => oAuth2Api.GetApplicationToken(OAuthEnvironment.PRODUCTION, null));
        }

        [Fact]
        public void GenerateUserAuthorizationUrl_Success() {
            string jsonFile = @"../../../ebay-config-sample.json";
            var fi = new FileInfo(jsonFile);
            var fs = fi.Open(FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read);
            CredentialUtil.Load(fs);

            string state = "State";
            string authorizationUrl = oAuth2Api.GenerateUserAuthorizationUrl(OAuthEnvironment.PRODUCTION, userScopes, state);
            Console.WriteLine("======================GenerateUserAuthorizationUrl======================");
            Console.WriteLine("AuthorizationUrl => " + authorizationUrl);
            Assert.NotNull(authorizationUrl);
        }

        [Fact]
        public void GenerateUserAuthorizationUrl_NullEnvironment_Failure()
        {
            Assert.Throws<ArgumentException>(() => oAuth2Api.GenerateUserAuthorizationUrl(null, scopes, null));
        }

        [Fact]
        public void GenerateUserAuthorizationUrl_NullScopes_Failure()
        {
            Assert.Throws<ArgumentException>(() => oAuth2Api.GenerateUserAuthorizationUrl(OAuthEnvironment.PRODUCTION, null, null));
        }

        [Fact]
        public void ExchangeCodeForAccessToken_Success()
        {
            OAuthEnvironment environment = OAuthEnvironment.PRODUCTION;
            string code = "v^1.1**********************jYw";
            OAuthResponse oAuthResponse = oAuth2Api.ExchangeCodeForAccessToken(environment, code);
            Assert.NotNull(oAuthResponse);
            PrintOAuthResponse(environment, "ExchangeCodeForAccessToken", oAuthResponse);
        }

        [Fact]
        public void ExchangeCodeForAccessToken_NullEnvironment_Failure()
        {
            string code = "v^1.1*********************MjYw";
            Assert.Throws<ArgumentException>(() => oAuth2Api.ExchangeCodeForAccessToken(null, code));
        }

        [Fact]
        public void ExchangeCodeForAccessToken_NullCode_Failure()
        {
            Assert.Throws<ArgumentException>(() => oAuth2Api.ExchangeCodeForAccessToken(OAuthEnvironment.PRODUCTION, null));
        }

        [Fact]
        public void GetAccessToken_Success()
        {
            OAuthEnvironment environment = OAuthEnvironment.PRODUCTION;
            string refreshToken = "v^1.1*****************I2MA==";
            OAuthResponse oAuthResponse = oAuth2Api.GetAccessToken(environment, refreshToken, userScopes);
            Assert.NotNull(oAuthResponse);
            PrintOAuthResponse(environment, "GetAccessToken", oAuthResponse);
        }

        [Fact]
        public void GetAccessToken_EndToEnd_Production()
        {
            Console.WriteLine("======================GetAccessToken_EndToEnd_Production======================");
            GetAccessToken_EndToEnd(OAuthEnvironment.PRODUCTION);
        }

        [Fact]
        public void GetAccessToken_EndToEnd_Sandbox()
        {
            Console.WriteLine("======================GetAccessToken_EndToEnd_Sandbox======================");
            GetAccessToken_EndToEnd(OAuthEnvironment.SANDBOX);
        }


        private void GetApplicationToken_Success(OAuthEnvironment environment) {
            OAuthResponse oAuthResponse = oAuth2Api.GetApplicationToken(environment, scopes);
            Assert.NotNull(oAuthResponse);
            PrintOAuthResponse(environment, "GetApplicationToken", oAuthResponse);
        }

        private void LoadCredentials() {
            string path = @"../../../ebay-config-sample.json";
            CredentialUtil.Load(path);
        }

        private void PrintOAuthResponse(OAuthEnvironment environment, string methodName, OAuthResponse oAuthResponse) {
            Console.WriteLine("======================" + methodName + "======================");
            Console.WriteLine("Environment=> " + environment.ConfigIdentifier() + ", ErroMessage=> " + oAuthResponse.ErrorMessage);
            if (oAuthResponse.AccessToken != null)
            {
                Console.WriteLine("AccessToken=> " + oAuthResponse.AccessToken.Token);
            }
            if (oAuthResponse.RefreshToken != null)
            {
                Console.WriteLine("RefreshToken=> " + oAuthResponse.RefreshToken.Token);
            }
        }

        private void GetAccessToken_EndToEnd(OAuthEnvironment environment)
        {
            //Load user credentials
            UserCredential userCredential = ReadUserNamePassword(environment);
            if ("<sandbox-username>".Equals(userCredential.UserName) || "<production-username>".Equals(userCredential.UserName) || "<sandbox-user-password>".Equals(userCredential.Pwd) || "<production-user-password>".Equals(userCredential.Pwd))
            {
                Console.WriteLine("User name and password are not specified in test-config-sample.json");
                return;
            }

            string authorizationUrl = oAuth2Api.GenerateUserAuthorizationUrl(environment, userScopes, null);
            Console.WriteLine("AuthorizationUrl => " + authorizationUrl);
            string authorizationCode = GetAuthorizationCode(authorizationUrl, userCredential);
            Console.WriteLine("AuthorizationCode => " + authorizationCode);
            OAuthResponse oAuthResponse = oAuth2Api.ExchangeCodeForAccessToken(environment, authorizationCode);
            Assert.NotNull(oAuthResponse);
            Assert.NotNull(oAuthResponse.RefreshToken);
            string refreshToken = oAuthResponse.RefreshToken.Token;
            Console.WriteLine("RefreshToken=> " + refreshToken);
            oAuthResponse = oAuth2Api.GetAccessToken(environment, refreshToken, userScopes);
            Assert.NotNull(oAuthResponse);
            Assert.NotNull(oAuthResponse.AccessToken);
            Console.WriteLine("AccessToken=> " + oAuthResponse.AccessToken.Token);
        }


        private UserCredential ReadUserNamePassword(OAuthEnvironment environment)
        {
            UserCredential userCredential = new UserCredential();
            
            FileInfo sampleConfig = new FileInfo("../../../test-config-sample.json");
            FileStream fs = sampleConfig.Open(FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read);
            var options = new JsonSerializerOptions{PropertyNameCaseInsensitive = true};
            var jsObj = JsonSerializer.Deserialize<Root>(fs, options);
        if(environment.ConfigIdentifier().Equals(OAuthEnvironment.PRODUCTION.ConfigIdentifier()))
        {
            userCredential.UserName = jsObj.ProductionUser.Username;
            userCredential.Pwd = jsObj.ProductionUser.Password;
        }
        else
        {
            userCredential.UserName = jsObj.SandboxUser.Username;
            userCredential.Pwd = jsObj.SandboxUser.Password;
        }
            return userCredential;
        }

        private string GetAuthorizationCode(string authorizationUrl, UserCredential userCredential) {

            IWebDriver driver = new ChromeDriver("./");

            //Submit login form
            driver.Navigate().GoToUrl(authorizationUrl);
            IWebElement userId = driver.FindElement(By.Id("userid"));
            IWebElement password = driver.FindElement(By.Id("pass"));
            IWebElement submit = driver.FindElement(By.Id("sgnBt"));
            userId.SendKeys(userCredential.UserName);
            password.SendKeys(userCredential.Pwd);
            submit.Click();

            //Wait for success page
            Thread.Sleep(2000);

            string successUrl = driver.Url;

            //Handle consent
            if(successUrl.Contains("/consents"))
            {
                IWebElement consent = driver.FindElement(By.Id("submit"));
                consent.Click();
                Thread.Sleep(2000);
                successUrl = driver.Url;
            }

            int iqs = successUrl.IndexOf('?');
            string querystring = (iqs < successUrl.Length - 1) ? successUrl.Substring(iqs + 1) : string.Empty;
            // Parse the query string variables into a NameValueCollection.
            NameValueCollection queryParams = HttpUtility.ParseQueryString(querystring);
            string code = queryParams.Get("code");
            driver.Quit();

            return code;

        }

    }
    
    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
    public class Root
    {
        [JsonPropertyName("sandbox-user")]
        public User SandboxUser { get; set; }

        [JsonPropertyName("production-user")]
        public User ProductionUser { get; set; }
    }
}
