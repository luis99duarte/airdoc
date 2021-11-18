// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;

namespace identity
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            var customProfile = new IdentityResource(
           name: "profile",
           displayName: "Profile Information",
           claimTypes: new[] { "display_name" });

            return new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                customProfile
            };
        }

        public static IEnumerable<ApiResource> GetApis()
        {
            return new ApiResource[] {
            new ApiResource{

                Name="FHIRAPI",
                ApiSecrets={
                    new Secret("secret".Sha256())
                },
                Scopes={
                new Scope()
                    {
                        Name = "FHIR_API.full_access",
                        DisplayName = "Full access to FHIR_API",
                        UserClaims={JwtClaimTypes.Role}

                    },
                    new Scope
                    {
                        Name = "FHIR_API.patient_access",
                        DisplayName = "Patient access to FHIR_API",
                        UserClaims={JwtClaimTypes.Role}
                    },
                     new Scope
                    {
                        Name = "FHIR_API.doctor_access",
                        DisplayName = "Doctor access to FHIR_API",
                        UserClaims={JwtClaimTypes.Role,"related"}

                    }
                }


                }

            };
        }

        public static IEnumerable<Client> GetClients()
        {

            return new Client[] {

             new Client
            {
                ClientId = "service.client", 
                ClientSecrets = { new Secret("secret".Sha256()) },
                RedirectUris={"https://airdoc.inspirers.med.up.pt/security/airdoc-openid/redirect"},
                AllowedGrantTypes = GrantTypes.Hybrid,
                AllowOfflineAccess=true,
                RequireConsent=false,

                AbsoluteRefreshTokenLifetime =  60 * 11520,  // 48h
                AccessTokenLifetime = 60 * 2880,            // 48h
                SlidingRefreshTokenLifetime = 60 * 2880,    // 48h

                AllowedScopes = { "openid","FHIR_API.patient_access","FHIR_API.doctor_access", "profile" },
            },
             new Client
            {
                ClientId = "caratm.client",
                ClientSecrets = { new Secret("secret".Sha256()) },
                RedirectUris={"https://caratm.inspirers.med.up.pt/security/caratm-openid/redirect"},

                // where to redirect to after logout
                // PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },

                AllowedGrantTypes = GrantTypes.Hybrid,
                AllowOfflineAccess=true,
                RequireConsent=false,

                RefreshTokenExpiration = TokenExpiration.Sliding,

                AbsoluteRefreshTokenLifetime =  60 * 11520,  // 48h
                AccessTokenLifetime = 60 * 2880,            // 48h
                SlidingRefreshTokenLifetime = 60 * 2880,    // 48h

                AllowedScopes = { "openid","FHIR_API.patient_access","FHIR_API.doctor_access", "profile" },
            },
            new Client
            {
                ClientId = "portalviewer",
                ClientSecrets = { new Secret("secret".Sha256()) },
                RedirectUris = { Environment.GetEnvironmentVariable("portal_url") + "/incomingToken" },
                AllowedGrantTypes = GrantTypes.Hybrid,
                AllowOfflineAccess = true,
                RequireConsent=false,
                AllowedScopes = { "openid", "FHIR_API.patient_access", "FHIR_API.doctor_access"},
            },
            };
        }
    }
}