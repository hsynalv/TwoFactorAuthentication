using System.Net;
using System.Net.Mail;
using Microsoft.AspNetCore.Identity;

namespace NetCoreIdentity.Helper
{
    public static class PasswordReset
    {

        public static void SendPasswordResetEmail(string link, string email)
        {
            //MailMessage mail = new MailMessage();

            //SmtpClient smtpClient = new SmtpClient("smtp.gmail.com", 587);

            //mail.From = new MailAddress("alavhasan72892@gmail");
            //mail.To.Add(email);

            //mail.Subject = $"www.bıdıbı.com::Şifre sıfırlama";
            //mail.Body = "<h2>Şifrenizi yenilemek için lütfen aşağıdaki linke tıklayınız.</h2><hr/>";
            //mail.Body += $"<a href='{link}'>şifre yenileme linki</a>";
            //mail.IsBodyHtml = true;
            //smtpClient.Port = 587;
            //smtpClient.Credentials = new NetworkCredential("", "");

            //smtpClient.Send(mail);
        }
    }
}
