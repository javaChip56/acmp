using System.Security.Cryptography.X509Certificates;
using System.Text;
using MyCompany.AuthPlatform.Application;

namespace MyCompany.AuthPlatform.Packaging;

public interface IX509CertificateResolver
{
    X509Certificate2 Resolve(HmacCredentialPackageProtectionBinding protectionBinding);
}

public sealed class CompositeX509CertificateResolver : IX509CertificateResolver
{
    public X509Certificate2 Resolve(HmacCredentialPackageProtectionBinding protectionBinding)
    {
        var bindingType = protectionBinding.BindingType?.Trim();

        if (string.Equals(bindingType, RecipientProtectionBindingTypes.X509StoreThumbprint, StringComparison.Ordinal))
        {
            return ResolveFromStore(protectionBinding);
        }

        if (string.Equals(bindingType, RecipientProtectionBindingTypes.X509File, StringComparison.Ordinal))
        {
            return ResolveFromFileOrPem(protectionBinding);
        }

        throw new ApplicationServiceException(400, "package_binding_invalid", "The requested protection binding type is not supported.");
    }

    private static X509Certificate2 ResolveFromStore(HmacCredentialPackageProtectionBinding protectionBinding)
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
            .FirstOrDefault(candidate =>
                string.Equals(NormalizeThumbprint(candidate.Thumbprint), normalizedThumbprint, StringComparison.OrdinalIgnoreCase));

        if (match is null)
        {
            throw new ApplicationServiceException(400, "package_binding_invalid", "The requested X.509 certificate could not be found.");
        }

        EnsureCertificateHasRsaKey(match);
        return match;
    }

    private static X509Certificate2 ResolveFromFileOrPem(HmacCredentialPackageProtectionBinding protectionBinding)
    {
        var certificatePem = NormalizeOptionalText(protectionBinding.CertificatePem);
        if (certificatePem is not null)
        {
            var pemCertificate = X509Certificate2.CreateFromPem(certificatePem);
            EnsureCertificateHasRsaKey(pemCertificate);
            return pemCertificate;
        }

        var certificatePath = NormalizeOptionalText(protectionBinding.CertificatePath)
            ?? throw new ApplicationServiceException(400, "package_binding_invalid", "The requested X.509 file binding requires 'certificatePath' or 'certificatePem'.");

        if (!File.Exists(certificatePath))
        {
            throw new ApplicationServiceException(400, "package_binding_invalid", "The requested X.509 certificate file could not be found.");
        }

        var extension = Path.GetExtension(certificatePath);
        X509Certificate2 certificate;

        if (string.Equals(extension, ".pem", StringComparison.OrdinalIgnoreCase))
        {
            var privateKeyPath = NormalizeOptionalText(protectionBinding.PrivateKeyPath);
            certificate = privateKeyPath is null
                ? X509Certificate2.CreateFromPemFile(certificatePath)
                : X509Certificate2.CreateFromPemFile(certificatePath, privateKeyPath);
        }
        else
        {
            certificate = new X509Certificate2(certificatePath);
        }

        EnsureCertificateHasRsaKey(certificate);
        return certificate;
    }

    private static void EnsureCertificateHasRsaKey(X509Certificate2 certificate)
    {
        if (certificate.GetRSAPublicKey() is null)
        {
            throw new ApplicationServiceException(400, "package_binding_invalid", "The requested X.509 certificate does not have an RSA public key.");
        }
    }

    private static string NormalizeThumbprint(string? thumbprint) =>
        string.Concat((thumbprint ?? string.Empty).Where(ch => !char.IsWhiteSpace(ch))).ToUpperInvariant();

    private static string? NormalizeOptionalText(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
