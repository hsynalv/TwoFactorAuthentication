using Microsoft.Extensions.Options;

namespace NetCoreIdentity.TwoFactorServices;

public class SmsSender
{
    private readonly TwoFactorOptions _twoFactorOptions;

    private readonly TwoFactorService _twoFactorService;

    public SmsSender(IOptions<TwoFactorOptions> options, TwoFactorService twoFactorService)
    {
        _twoFactorOptions = options.Value;
        _twoFactorService = twoFactorService;
    }

    public string Send(string phone)
    {
        string code = _twoFactorService.GetCodeVerification().ToString();

        //SMS PROVIDER CODES

        //return code;
        return "1896";
    }
}