using System.Security.Cryptography.X509Certificates;
using MyCompany.AuthPlatform.Application;

namespace MyCompany.AuthPlatform.Packaging;

public interface IX509CertificateResolver
{
    X509Certificate2 Resolve(HmacCredentialPackageProtectionBinding protectionBinding);
}

public sealed class StoreX509CertificateResolver : IX509CertificateResolver
{
    public X509Certificate2 Resolve(HmacCredentialPackageProtectionBinding protectionBinding)
    {
        if (!Enum.TryParse<StoreLocation>(protectionBinding.StoreLocation, ignoreCase: true, out var storeLocation))
        {
            throw new ApplicationServiceException(400, "package_binding_invalid", "The requested certificate store location is not supported.");
        }

        if (!Enum.TryParse<StoreName>(protectionBinding.StoreName, ignoreCase: true, out var storeName))
        {
            throw new ApplicationServiceException(400, "package_binding_invalid", "The requested certificate store name is not supported.");
        }

        var normalizedThumbprint = NormalizeThumbprint(protectionBinding.CertificateThumbprint);
        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadOnly);

        var match = store.Certificates
            .OfType<X509Certificate2>()
            .FirstOrDefault(certificate =>
                string.Equals(NormalizeThumbprint(certificate.Thumbprint), normalizedThumbprint, StringComparison.OrdinalIgnoreCase));

        if (match is null)
        {
            throw new ApplicationServiceException(400, "package_binding_invalid", "The requested X.509 certificate could not be found.");
        }

        if (match.GetRSAPublicKey() is null)
        {
            throw new ApplicationServiceException(400, "package_binding_invalid", "The requested X.509 certificate does not have an RSA public key.");
        }

        return match;
    }

    private static string NormalizeThumbprint(string? thumbprint) =>
        string.Concat((thumbprint ?? string.Empty).Where(ch => !char.IsWhiteSpace(ch))).ToUpperInvariant();
}
