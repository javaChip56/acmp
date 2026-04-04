using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace MyCompany.AuthPlatform.Hmac;

public sealed record HmacSignatureHeaders(
    string KeyId,
    string Signature,
    string Timestamp,
    string? Nonce);

public static class HmacCanonicalRequestBuilder
{
    private const string TimestampFormat = "yyyy-MM-ddTHH:mm:ssZ";

    public static string Build(
        string method,
        string path,
        string? queryString,
        ReadOnlySpan<byte> body,
        string timestamp,
        string? nonce,
        string keyId)
    {
        var normalizedMethod = RequireText(method, nameof(method)).ToUpperInvariant();
        var normalizedPath = NormalizePath(path);
        var canonicalQuery = NormalizeQueryString(queryString);
        var bodyHash = ComputeBodyHash(body);
        var normalizedTimestamp = RequireText(timestamp, nameof(timestamp));
        var normalizedNonce = nonce?.Trim() ?? string.Empty;
        var normalizedKeyId = RequireText(keyId, nameof(keyId));

        return string.Join(
            '\n',
            normalizedMethod,
            normalizedPath,
            canonicalQuery,
            bodyHash,
            normalizedTimestamp,
            normalizedNonce,
            normalizedKeyId);
    }

    public static string FormatTimestamp(DateTimeOffset timestamp) =>
        timestamp.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture);

    public static bool TryParseTimestamp(string? value, out DateTimeOffset timestamp) =>
        DateTimeOffset.TryParseExact(
            value,
            TimestampFormat,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out timestamp);

    public static string ComputeBodyHash(ReadOnlySpan<byte> body) =>
        ConvertToLowerHex(SHA256.HashData(body));

    public static string ComputeSignatureHex(byte[] secret, string canonicalString)
    {
        using var hmac = new HMACSHA256(secret);
        return ConvertToLowerHex(hmac.ComputeHash(Encoding.UTF8.GetBytes(canonicalString)));
    }

    public static bool FixedTimeEqualsHex(string left, string right)
    {
        var leftBytes = Encoding.ASCII.GetBytes(left);
        var rightBytes = Encoding.ASCII.GetBytes(right);
        return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private static string NormalizePath(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return "/";
        }

        var rawPath = path[0] == '/' ? path : "/" + path;
        return PercentEncode(rawPath, allowSlash: true);
    }

    private static string NormalizeQueryString(string? queryString)
    {
        if (string.IsNullOrEmpty(queryString))
        {
            return string.Empty;
        }

        var rawQuery = queryString[0] == '?' ? queryString[1..] : queryString;
        if (rawQuery.Length == 0)
        {
            return string.Empty;
        }

        var pairs = rawQuery
            .Split('&', StringSplitOptions.None)
            .Select(segment =>
            {
                var separatorIndex = segment.IndexOf('=');
                var rawName = separatorIndex >= 0 ? segment[..separatorIndex] : segment;
                var rawValue = separatorIndex >= 0 ? segment[(separatorIndex + 1)..] : string.Empty;

                return new CanonicalQueryPair(
                    PercentEncode(rawName, allowSlash: false),
                    PercentEncode(rawValue, allowSlash: false));
            })
            .OrderBy(pair => pair.Name, StringComparer.Ordinal)
            .ThenBy(pair => pair.Value, StringComparer.Ordinal)
            .Select(pair => $"{pair.Name}={pair.Value}");

        return string.Join('&', pairs);
    }

    private static string PercentEncode(string value, bool allowSlash)
    {
        var builder = new StringBuilder(value.Length);
        Span<byte> utf8Buffer = stackalloc byte[4];

        for (var index = 0; index < value.Length;)
        {
            if (value[index] == '%' &&
                index + 2 < value.Length &&
                IsHex(value[index + 1]) &&
                IsHex(value[index + 2]))
            {
                builder.Append('%');
                builder.Append(char.ToUpperInvariant(value[index + 1]));
                builder.Append(char.ToUpperInvariant(value[index + 2]));
                index += 3;
                continue;
            }

            var status = Rune.DecodeFromUtf16(value.AsSpan(index), out var rune, out var charsConsumed);
            if (status != OperationStatus.Done)
            {
                throw new InvalidOperationException("The request path or query contains invalid UTF-16 data.");
            }

            if (IsAllowed(rune, allowSlash))
            {
                builder.Append(rune.ToString());
            }
            else
            {
                if (!rune.TryEncodeToUtf8(utf8Buffer, out var bytesWritten))
                {
                    throw new InvalidOperationException("The request path or query contains a rune that could not be encoded as UTF-8.");
                }

                for (var byteIndex = 0; byteIndex < bytesWritten; byteIndex++)
                {
                    builder.Append('%');
                    builder.Append(utf8Buffer[byteIndex].ToString("X2", CultureInfo.InvariantCulture));
                }
            }

            index += charsConsumed;
        }

        return builder.ToString();
    }

    private static string ConvertToLowerHex(ReadOnlySpan<byte> bytes)
    {
        var builder = new StringBuilder(bytes.Length * 2);
        foreach (var value in bytes)
        {
            builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }

    private static bool IsAllowed(Rune rune, bool allowSlash) =>
        rune.Value switch
        {
            >= 'A' and <= 'Z' => true,
            >= 'a' and <= 'z' => true,
            >= '0' and <= '9' => true,
            '-' or '_' or '.' or '~' => true,
            '/' => allowSlash,
            _ => false,
        };

    private static bool IsHex(char value) =>
        value is >= '0' and <= '9' or >= 'A' and <= 'F' or >= 'a' and <= 'f';

    private static string RequireText(string? value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"'{paramName}' is required.", paramName);
        }

        return value.Trim();
    }

    private sealed record CanonicalQueryPair(string Name, string Value);
}
