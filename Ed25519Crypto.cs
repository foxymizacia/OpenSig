using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace OpenSig;

/// <summary>
/// Pure Ed25519 (RFC 8032): exactly the 64 raw signature bytes that OpenSSL
/// 'pkeyutl -sign/-verify -rawin' generates/expects (NOT Ed25519ph).
/// BouncyCastle's Ed25519Signer buffers its message, unlike the RSA/SHA-256 path.
/// </summary>
internal static class Ed25519Crypto
{
    // Pure Ed25519 is one-shot. Keep ordinary desktop machines safe from
    // unbounded managed-memory allocations by setting an explicit upper bound.
    // RSA/SHA-256 has no such file-size limit and processes data as a stream.
    public const long MaxFileSize = 256L * 1024 * 1024;

    public static (string PrivatePem, string PublicPem) GeneratePemPair()
    {
        var privateKey = new Ed25519PrivateKeyParameters(new SecureRandom());
        var publicKey = privateKey.GeneratePublicKey();
        return (
            ToPem("PRIVATE KEY", PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetEncoded()),
            ToPem("PUBLIC KEY", SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).GetEncoded())
        );
    }

    public static Ed25519PrivateKeyParameters LoadPrivateKey(string pem, string password)
    {
        var encrypted = pem.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal);
        var der = FromPem(pem, encrypted ? "ENCRYPTED PRIVATE KEY" : "PRIVATE KEY");
        var key = encrypted
            ? PrivateKeyFactory.DecryptKey(password.ToCharArray(), der)
            : PrivateKeyFactory.CreateKey(der);
        return key as Ed25519PrivateKeyParameters
            ?? throw new CryptographicException("Выбранный закрытый ключ не является Ed25519. Измените алгоритм или ключ.");
    }

    public static Ed25519PublicKeyParameters LoadPublicKey(string pem)
    {
        var key = PublicKeyFactory.CreateKey(FromPem(pem, "PUBLIC KEY"));
        return key as Ed25519PublicKeyParameters
            ?? throw new CryptographicException("Выбранный открытый ключ не является Ed25519. Измените алгоритм или ключ.");
    }

    public static OperationResult SignFile(Ed25519PrivateKeyParameters key, string filePath, string signaturePath)
    {
        try
        {
            var size = new FileInfo(filePath).Length;
            if (size > MaxFileSize)
                return FileTooLarge(filePath);

            var signer = new Ed25519Signer();
            signer.Init(true, key);
            FeedFile(signer, filePath);
            var signature = signer.GenerateSignature();

            // Never leave a partial .sig if writing fails.
            var temp = signaturePath + ".tmp_" + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllBytes(temp, signature);
                File.Move(temp, signaturePath, overwrite: true);
            }
            finally
            {
                try { if (File.Exists(temp)) File.Delete(temp); } catch { /* best effort */ }
            }
            return new OperationResult(filePath, "Подписан", signaturePath, true);
        }
        catch (Exception ex)
        {
            return new OperationResult(filePath, "Ошибка", ex.Message, false);
        }
    }

    public static OperationResult VerifyFile(Ed25519PublicKeyParameters key, string droppedPath)
    {
        string filePath;
        string signaturePath;
        if (droppedPath.EndsWith(".sig", StringComparison.OrdinalIgnoreCase))
        {
            signaturePath = droppedPath;
            filePath = droppedPath[..^4];
        }
        else
        {
            filePath = droppedPath;
            signaturePath = droppedPath + ".sig";
        }

        if (!File.Exists(filePath))
            return new OperationResult(droppedPath, "Не найден файл", filePath, false);
        if (!File.Exists(signaturePath))
            return new OperationResult(droppedPath, "Нет .sig", signaturePath, false);

        try
        {
            if (new FileInfo(signaturePath).Length != 64)
                return new OperationResult(droppedPath, "НЕВЕРНА", "Подпись Ed25519 должна быть ровно 64 байта", false);
            if (new FileInfo(filePath).Length > MaxFileSize)
                return FileTooLarge(droppedPath);

            var signature = File.ReadAllBytes(signaturePath);
            var verifier = new Ed25519Signer();
            verifier.Init(false, key);
            FeedFile(verifier, filePath);
            var valid = verifier.VerifySignature(signature);
            return valid
                ? new OperationResult(droppedPath, "Подпись верна", signaturePath, true)
                : new OperationResult(droppedPath, "НЕВЕРНА", "Файл, подпись или открытый ключ не совпадают", false);
        }
        catch (Exception ex)
        {
            return new OperationResult(droppedPath, "Ошибка", ex.Message, false);
        }
    }

    private static void FeedFile(Ed25519Signer signer, string filePath)
    {
        // NOTE: BlockUpdate is a streaming *interface*, but the pure Ed25519
        // implementation buffers all chunks internally until signing/verifying.
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var buffer = new byte[64 * 1024];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            signer.BlockUpdate(buffer, 0, read);
    }

    private static OperationResult FileTooLarge(string path) =>
        new(path, "Слишком большой", "Для Ed25519 максимум 256 МиБ (ограничение памяти). Для больших файлов выберите RSA / SHA-256.", false);

    private static string ToPem(string label, byte[] der)
    {
        var base64 = Convert.ToBase64String(der);
        using var writer = new StringWriter();
        writer.WriteLine($"-----BEGIN {label}-----");
        for (var index = 0; index < base64.Length; index += 64)
            writer.WriteLine(base64.Substring(index, Math.Min(64, base64.Length - index)));
        writer.WriteLine($"-----END {label}-----");
        return writer.ToString();
    }

    private static byte[] FromPem(string pem, string label)
    {
        var begin = $"-----BEGIN {label}-----";
        var end = $"-----END {label}-----";
        var start = pem.IndexOf(begin, StringComparison.Ordinal);
        if (start < 0)
            throw new CryptographicException($"В PEM не найден блок {label}.");
        start += begin.Length;
        var stop = pem.IndexOf(end, start, StringComparison.Ordinal);
        if (stop < 0)
            throw new CryptographicException($"Незакрытый PEM-блок {label}.");
        return Convert.FromBase64String(pem[start..stop]);
    }
}
