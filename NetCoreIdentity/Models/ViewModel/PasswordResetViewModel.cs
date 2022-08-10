using System.ComponentModel.DataAnnotations;

namespace NetCoreIdentity.Models.ViewModel
{
    public class PasswordResetViewModel
    {
        [Required(ErrorMessage = "E-posta adresini girmek zorunludur.")]
        [Display(Name = "E-posta")]
        [EmailAddress]
        public string Email { get; set; }

        [Display(Name = "Yeni şifreniz")]
        [Required(ErrorMessage = "Şifre alanı gereklidir")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "şifreniz en az 4 karakterli olmalıdır.")]
        public string PasswordNew { get; set; }
    }
}
