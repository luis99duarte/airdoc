﻿// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;

namespace identity.Controllers
{
    public class AccountOptions
    {
        public static bool AllowLocalLogin = true;
        public static bool AllowRememberLogin = false;
        public static TimeSpan RememberMeLoginDuration = TimeSpan.FromDays(200);

        public static bool ShowLogoutPrompt = true;
        public static bool AutomaticRedirectAfterSignOut = false;

        // specify the Windows authentication scheme being used
        public static readonly string WindowsAuthenticationSchemeName = Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.AuthenticationScheme;
        // if user uses windows auth, should we load the groups from windows
        public static bool IncludeWindowsGroups = false;

        public static string InvalidCredentialsErrorMessage = "As credênciais inseridas não são válidas";
        public static string InvalidRegistrationErrorMessage = "O utilizador já existe";
        public static string InvalidPasswordIdenticalErrorMessage = "As passwords indicadas não coincidem";
        public static string InvalidEmailIdenticalErrorMessage = "Os emails indicadoos não coincidem";
        public static string EmailAlreadyRegistered = "Este email já está registado noutra conta";
        public static string InvalidPasswordValidation = "A password não cumpre algum dos requisitos de ter no mínimo de 6 caracteres, pelo menos 1 letra minúscula, 1 letra maiúscula e 1 número";
    }
}
