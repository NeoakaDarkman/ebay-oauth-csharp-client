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
using System.Collections.Generic;
using System.IO;
using eBay.ApiClient.Auth.OAuth2.Model;
using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace eBay.ApiClient.Auth.OAuth2
{
    public static class CredentialUtil
    {
        private static ILogger log = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
        }).CreateLogger<Credentials>();
        static readonly ConcurrentDictionary<string, Credentials> envCredentials = new ConcurrentDictionary<string, Credentials>();

        public class Credentials {
            private readonly Dictionary<CredentialType, string> credentialTypeLookup = new Dictionary<CredentialType, string>();

            public Credentials(ConfigCredential credential)
            {
                CredentialType credentialType = CredentialType.LookupByConfigIdentifier(nameof(credential.AppId).ToLower());
                if (credentialType != null)
                {
                    credentialTypeLookup.Add(credentialType, credential.AppId);
                }
                credentialType = CredentialType.LookupByConfigIdentifier(nameof(credential.CertId).ToLower());
                if (credentialType != null)
                {
                    credentialTypeLookup.Add(credentialType, credential.CertId);
                }
                credentialType = CredentialType.LookupByConfigIdentifier(nameof(credential.DevId).ToLower());
                if (credentialType != null)
                {
                    credentialTypeLookup.Add(credentialType, credential.DevId);
                }
                credentialType = CredentialType.LookupByConfigIdentifier(nameof(credential.RedirectUri).ToLower());
                if (credentialType != null)
                {
                    credentialTypeLookup.Add(credentialType, credential.RedirectUri);
                }
            }

            public string Get(CredentialType credentialType)
            {
                return credentialTypeLookup[credentialType];
            }
        }

        /*
         * Loading StreamReader
         */
        public static void Load(string jsonFile)
        {
            //Stream the input file
            var fi = new FileInfo(jsonFile);
            var fs = fi.Open(FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read);
            Load(fs);
        }

        /*
         * Loading YAML file
         */
        public static void Load(Stream stream)
        {
           
            var options = new JsonSerializerOptions{PropertyNameCaseInsensitive = true};
            var jsObj = JsonSerializer.Deserialize<JsonConfig>(stream, options);

            foreach (var cc in jsObj.Credentials)
            {
                OAuthEnvironment environment = OAuthEnvironment.LookupByConfigIdentifier(cc.Environment);
                Credentials credentials = new Credentials(cc);
                envCredentials[environment.ConfigIdentifier()] = credentials;
            }
            log.LogInformation("Loaded configuration for eBay oAuth Token");

        }

        /*
         * Get Credentials based on Environment
         */
        public static Credentials GetCredentials(OAuthEnvironment environment) {

            return envCredentials.TryGetValue(environment.ConfigIdentifier(), out Credentials credentials) ? credentials : null;
        }

    }
}
