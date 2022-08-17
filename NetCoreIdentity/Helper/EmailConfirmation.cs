using System.Net;
using System.Net.Mail;

namespace NetCoreIdentity.Helper
{
    public static class EmailConfirmation
    {
        public static void SendEmail(string link, string email)
        {
            //MailMessage mail = new MailMessage();

            //SmtpClient smtpClient = new SmtpClient("smtp.gmail.com", 587);

            //mail.From = new MailAddress("alavhasan72892@gmail");
            //mail.To.Add(email);

            //mail.Subject = $"www.bıdıbı.com::Email Doğrulama";
            //mail.Body = "<h2>email Adresinizi doğrulamak için lütfen aşağıdaki linke tıklayınız.</h2><hr/>";
            //mail.Body += $"<a href='{link}'>email doğrulama linki</a>";
            //mail.IsBodyHtml = true;
            //smtpClient.Port = 587;
            //smtpClient.Credentials = new NetworkCredential("", "");

            //smtpClient.Send(mail);
        }
    }
}
