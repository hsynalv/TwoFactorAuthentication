using System.ComponentModel.DataAnnotations;

namespace NetCoreIdentity.Models.ViewModel
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "E-posta adresini girmek zorunludur.")]
        [Display(Name = "E-posta")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Parola girmek zorunludur.")]
        [DataType(DataType.Password)]
        [Display(Name = "Parola")]
        [MinLength(4, ErrorMessage = "Parola en az 4 karakter olmalıdır.")]
        public string Password { get; set; }

    }
}
