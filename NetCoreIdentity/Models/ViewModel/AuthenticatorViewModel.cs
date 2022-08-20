﻿using System.ComponentModel.DataAnnotations;
using NetCoreIdentity.Enums;

namespace NetCoreIdentity.Models.ViewModel;

public class AuthenticatorViewModel
{
    public string SharedKey { get; set; }

    public string AuthenticatorUri { get; set; }

    [Display(Name = "Doğrulama Kodunuz")]
    [Required(ErrorMessage = "Doğrulama kodu gereklidir")]
    public string VerificationCode { get; set; }

    [Display(Name = "İki adımlı kimlik doğrulama tipi")]
    public TwoFactor TwoFactorType { get; set; }
}