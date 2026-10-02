using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace XlsxCrypt;

public static class ExcelEncryption
{
    /// <summary>
    /// Encrypts an unencrypted .xlsx file using Office Agile Encryption.
    /// </summary>
    public static void EncryptFile(
        string inputFile,
        string outputFile,
        string password)
    {
        NativeExcelEncryption.EncryptFile(
            inputFile,
            outputFile,
            password);
    }

    /// <summary>
    /// Decrypts an Office Agile Encryption protected .xlsx file.
    /// </summary>
    public static void DecryptFile(
        string inputFile,
        string outputFile,
        string password)
    {
        NativeExcelEncryption.DecryptFile(
            inputFile,
            outputFile,
            password);
    }
}

internal sealed class NativeExcelEncryption
{
    private const int SaltSize = 16;
    private const int BlockSize = 16;
    private const int KeySize = 32;
    private const int HashSize = 64;
    private const int SpinCount = 100_000;
    private const int SegmentSize = 4096;

    private static readonly byte[] BlockKeyVerifierHashInput =
    {
        0xFE, 0xA7, 0xD2, 0x76,
        0x3B, 0x4B, 0x9E, 0x79
    };

    private static readonly byte[] BlockKeyEncryptedVerifierHashValue =
    {
        0xD7, 0xAA, 0x0F, 0x6D,
        0x30, 0x61, 0x34, 0x4E
    };

    private static readonly byte[] BlockKeyEncryptedKeyValue =
    {
        0x14, 0x6E, 0x0B, 0xE7,
        0xAB, 0xAC, 0xD0, 0xD6
    };

    private static readonly byte[] BlockKeyDataIntegrity1 =
    {
        0x5F, 0xB2, 0xAD, 0x01,
        0x0C, 0xB9, 0xE1, 0xF6
    };

    private static readonly byte[] BlockKeyDataIntegrity2 =
    {
        0xA0, 0x67, 0x7F, 0x02,
        0xB2, 0x2C, 0x84, 0x33
    };

    private readonly string _password;

    private readonly byte[] _passwordSalt;
    private readonly byte[] _keyDataSalt;
    private readonly byte[] _secretKey;
    private readonly byte[] _verifierHashInput;

    private byte[]? _encryptedHmacKey;
    private byte[]? _encryptedHmacValue;

    private byte[]? _encryptedVerifierHashInput;
    private byte[]? _encryptedVerifierHashValue;
    private byte[]? _encryptedKeyValue;

    private NativeExcelEncryption(
        string password,
        byte[] passwordSalt,
        byte[] keyDataSalt,
        byte[] secretKey,
        byte[] verifierHashInput)
    {
        _password = password;
        _passwordSalt = passwordSalt;
        _keyDataSalt = keyDataSalt;
        _secretKey = secretKey;
        _verifierHashInput = verifierHashInput;
    }

    // ========================================================================
    // PUBLIC API
    // ========================================================================

    public static void EncryptFile(
        string inputFile,
        string outputFile,
        string password)
    {
        ValidateFileArguments(
            inputFile,
            outputFile,
            password);

        if (!File.Exists(inputFile))
        {
            throw new FileNotFoundException(
                "Input Excel file was not found.",
                inputFile);
        }

        string fullInput =
            Path.GetFullPath(inputFile);

        string fullOutput =
            Path.GetFullPath(outputFile);

        if (string.Equals(
                fullInput,
                fullOutput,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "Input and output files must be different.",
                nameof(outputFile));
        }

        byte[] originalPackage =
            File.ReadAllBytes(inputFile);

        NativeExcelEncryption encryption =
            Create(password);

        byte[] encryptedPackage =
            encryption.EncryptPackage(originalPackage);

        encryption.GenerateIntegrity(encryptedPackage);

        byte[] encryptionInfo =
            encryption.CreateEncryptionInfo();

        OleCompoundFile.Create(
            encryptionInfo,
            encryptedPackage,
            outputFile);
    }

    public static void DecryptFile(
        string inputFile,
        string outputFile,
        string password)
    {
        ValidateFileArguments(
            inputFile,
            outputFile,
            password);

        if (!File.Exists(inputFile))
        {
            throw new FileNotFoundException(
                "Encrypted Excel file was not found.",
                inputFile);
        }

        string fullInput =
            Path.GetFullPath(inputFile);

        string fullOutput =
            Path.GetFullPath(outputFile);

        if (string.Equals(
                fullInput,
                fullOutput,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "Input and output files must be different.",
                nameof(outputFile));
        }

        OleCompoundFile.Read(
            inputFile,
            out byte[] encryptionInfo,
            out byte[] encryptedPackage);

        byte[] originalPackage =
            DecryptPackage(
                encryptionInfo,
                encryptedPackage,
                password);

        string? directory =
            Path.GetDirectoryName(fullOutput);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllBytes(
            outputFile,
            originalPackage);
    }

    private static void ValidateFileArguments(
        string inputFile,
        string outputFile,
        string password)
    {
        if (string.IsNullOrWhiteSpace(inputFile))
        {
            throw new ArgumentException(
                "Input file cannot be empty.",
                nameof(inputFile));
        }

        if (string.IsNullOrWhiteSpace(outputFile))
        {
            throw new ArgumentException(
                "Output file cannot be empty.",
                nameof(outputFile));
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException(
                "Password cannot be empty.",
                nameof(password));
        }
    }

    // ========================================================================
    // CREATION
    // ========================================================================

    public static NativeExcelEncryption Create(
        string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException(
                "Password cannot be empty.",
                nameof(password));
        }

        byte[] passwordSalt =
            RandomNumberGenerator.GetBytes(
                SaltSize);

        byte[] keyDataSalt =
            RandomNumberGenerator.GetBytes(
                SaltSize);

        byte[] secretKey =
            RandomNumberGenerator.GetBytes(
                KeySize);

        byte[] verifierHashInput =
            RandomNumberGenerator.GetBytes(
                SaltSize);

        NativeExcelEncryption encryption =
            new NativeExcelEncryption(
                password,
                passwordSalt,
                keyDataSalt,
                secretKey,
                verifierHashInput);

        encryption.GeneratePasswordEncryptionValues();

        return encryption;
    }

    // ========================================================================
    // KEY DERIVATION
    // ========================================================================

    private byte[] DerivePasswordHash()
    {
        return DerivePasswordHash(
            _passwordSalt,
            _password,
            SpinCount);
    }

    private static byte[] DerivePasswordHash(
        byte[] salt,
        string password,
        int spinCount)
    {
        byte[] passwordBytes =
            Encoding.Unicode.GetBytes(
                password);

        byte[] hash =
            SHA512.HashData(
                Combine(
                    salt,
                    passwordBytes));

        for (uint i = 0; i < (uint)spinCount; i++)
        {
            hash =
                SHA512.HashData(
                    Combine(
                        UInt32LittleEndian(i),
                        hash));
        }

        return hash;
    }

    private static byte[] DeriveEncryptionKey(
        byte[] passwordHash,
        byte[] blockKey)
    {
        byte[] hash =
            SHA512.HashData(
                Combine(
                    passwordHash,
                    blockKey));

        byte[] key =
            new byte[KeySize];

        Buffer.BlockCopy(
            hash,
            0,
            key,
            0,
            KeySize);

        return key;
    }

    // ========================================================================
    // PASSWORD VERIFIER / SECRET KEY
    // ========================================================================

    private void GeneratePasswordEncryptionValues()
    {
        byte[] passwordHash =
            DerivePasswordHash();

        byte[] verifierInputKey =
            DeriveEncryptionKey(
                passwordHash,
                BlockKeyVerifierHashInput);

        byte[] verifierHashValueKey =
            DeriveEncryptionKey(
                passwordHash,
                BlockKeyEncryptedVerifierHashValue);

        byte[] encryptedKeyValueKey =
            DeriveEncryptionKey(
                passwordHash,
                BlockKeyEncryptedKeyValue);

        // ------------------------------------------------------------
        // encryptedVerifierHashInput
        // ------------------------------------------------------------

        _encryptedVerifierHashInput =
            EncryptAesCbcNoPadding(
                _verifierHashInput,
                verifierInputKey,
                _passwordSalt);

        // ------------------------------------------------------------
        // encryptedVerifierHashValue
        // ------------------------------------------------------------

        byte[] verifierHash =
            SHA512.HashData(
                _verifierHashInput);

        _encryptedVerifierHashValue =
            EncryptAesCbcPaddedZero(
                verifierHash,
                verifierHashValueKey,
                _passwordSalt);

        // ------------------------------------------------------------
        // encryptedKeyValue
        // ------------------------------------------------------------

        _encryptedKeyValue =
            EncryptAesCbcPaddedZero(
                _secretKey,
                encryptedKeyValueKey,
                _passwordSalt);
    }

    // ========================================================================
    // ENCRYPTED PACKAGE
    // ========================================================================

    public byte[] EncryptPackage(
        byte[] originalPackage)
    {
        using MemoryStream output =
            new MemoryStream();

        // First 8 bytes = original unencrypted package size.
        WriteUInt64(
            output,
            (ulong)originalPackage.Length);

        int offset = 0;
        int segmentNumber = 0;

        while (offset < originalPackage.Length)
        {
            int remaining =
                originalPackage.Length - offset;

            int count =
                Math.Min(
                    SegmentSize,
                    remaining);

            byte[] chunk =
                new byte[count];

            Buffer.BlockCopy(
                originalPackage,
                offset,
                chunk,
                0,
                count);

            byte[] iv =
                GeneratePackageIv(
                    _keyDataSalt,
                    segmentNumber);

            byte[] encrypted =
                EncryptAesCbcPaddedZero(
                    chunk,
                    _secretKey,
                    iv);

            output.Write(
                encrypted,
                0,
                encrypted.Length);

            offset += count;
            segmentNumber++;
        }

        return output.ToArray();
    }

    private static byte[] GeneratePackageIv(
        byte[] keyDataSalt,
        int segmentNumber)
    {
        byte[] segment =
            UInt32LittleEndian(
                unchecked((uint)segmentNumber));

        byte[] hash =
            SHA512.HashData(
                Combine(
                    keyDataSalt,
                    segment));

        byte[] iv =
            new byte[BlockSize];

        Buffer.BlockCopy(
            hash,
            0,
            iv,
            0,
            BlockSize);

        return iv;
    }

    // ========================================================================
    // DATA INTEGRITY
    // ========================================================================

    public void GenerateIntegrity(
        byte[] encryptedPackage)
    {
        byte[] hmacKey =
            RandomNumberGenerator.GetBytes(
                HashSize);

        byte[] hmacValue;

        using (HMACSHA512 hmac =
               new HMACSHA512(hmacKey))
        {
            hmacValue =
                hmac.ComputeHash(
                    encryptedPackage);
        }

        byte[] iv1 =
            GenerateIntegrityIv(
                _keyDataSalt,
                BlockKeyDataIntegrity1);

        byte[] iv2 =
            GenerateIntegrityIv(
                _keyDataSalt,
                BlockKeyDataIntegrity2);

        _encryptedHmacKey =
            EncryptAesCbcNoPadding(
                hmacKey,
                _secretKey,
                iv1);

        _encryptedHmacValue =
            EncryptAesCbcNoPadding(
                hmacValue,
                _secretKey,
                iv2);
    }

    private static byte[] GenerateIntegrityIv(
        byte[] keyDataSalt,
        byte[] blockKey)
    {
        byte[] hash =
            SHA512.HashData(
                Combine(
                    keyDataSalt,
                    blockKey));

        byte[] iv =
            new byte[BlockSize];

        Buffer.BlockCopy(
            hash,
            0,
            iv,
            0,
            BlockSize);

        return iv;
    }

    // ========================================================================
    // ENCRYPTION INFO
    // ========================================================================

    public byte[] CreateEncryptionInfo()
    {
        if (_encryptedHmacKey == null ||
            _encryptedHmacValue == null ||
            _encryptedVerifierHashInput == null ||
            _encryptedVerifierHashValue == null ||
            _encryptedKeyValue == null)
        {
            throw new InvalidOperationException(
                "Encryption values have not been generated.");
        }

        string passwordSalt =
            Convert.ToBase64String(
                _passwordSalt);

        string keyDataSalt =
            Convert.ToBase64String(
                _keyDataSalt);

        string encryptedHmacKey =
            Convert.ToBase64String(
                _encryptedHmacKey);

        string encryptedHmacValue =
            Convert.ToBase64String(
                _encryptedHmacValue);

        string encryptedVerifierHashInput =
            Convert.ToBase64String(
                _encryptedVerifierHashInput);

        string encryptedVerifierHashValue =
            Convert.ToBase64String(
                _encryptedVerifierHashValue);

        string encryptedKeyValue =
            Convert.ToBase64String(
                _encryptedKeyValue);

        string xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<encryption xmlns=\"http://schemas.microsoft.com/office/2006/encryption\" " +
            "xmlns:p=\"http://schemas.microsoft.com/office/2006/keyEncryptor/password\">" +
            "<keyData " +
            "saltSize=\"16\" " +
            "blockSize=\"16\" " +
            "keyBits=\"256\" " +
            "hashSize=\"64\" " +
            "cipherAlgorithm=\"AES\" " +
            "cipherChaining=\"ChainingModeCBC\" " +
            "hashAlgorithm=\"SHA512\" " +
            $"saltValue=\"{keyDataSalt}\" />" +
            "<dataIntegrity " +
            $"encryptedHmacKey=\"{encryptedHmacKey}\" " +
            $"encryptedHmacValue=\"{encryptedHmacValue}\" />" +
            "<keyEncryptors>" +
            "<keyEncryptor " +
            "uri=\"http://schemas.microsoft.com/office/2006/keyEncryptor/password\">" +
            "<p:encryptedKey " +
            "spinCount=\"100000\" " +
            "saltSize=\"16\" " +
            "blockSize=\"16\" " +
            "keyBits=\"256\" " +
            "hashSize=\"64\" " +
            "cipherAlgorithm=\"AES\" " +
            "cipherChaining=\"ChainingModeCBC\" " +
            "hashAlgorithm=\"SHA512\" " +
            $"saltValue=\"{passwordSalt}\" " +
            $"encryptedVerifierHashInput=\"{encryptedVerifierHashInput}\" " +
            $"encryptedVerifierHashValue=\"{encryptedVerifierHashValue}\" " +
            $"encryptedKeyValue=\"{encryptedKeyValue}\" />" +
            "</keyEncryptor>" +
            "</keyEncryptors>" +
            "</encryption>";

        byte[] xmlBytes =
            Encoding.UTF8.GetBytes(
                xml);

        using MemoryStream ms =
            new MemoryStream();

        // Version major = 4
        WriteUInt16(
            ms,
            4);

        // Version minor = 4
        WriteUInt16(
            ms,
            4);

        // Reserved / Agile flag
        WriteUInt32(
            ms,
            0x40);

        ms.Write(
            xmlBytes,
            0,
            xmlBytes.Length);

        return ms.ToArray();
    }

    // ========================================================================
    // DECRYPTION
    // ========================================================================

    public static byte[] DecryptPackage(
        byte[] encryptionInfo,
        byte[] encryptedPackage,
        string password)
    {
        if (encryptionInfo.Length < 8)
        {
            throw new InvalidDataException(
                "Invalid EncryptionInfo stream.");
        }

        if (encryptedPackage.Length < 8)
        {
            throw new InvalidDataException(
                "Invalid EncryptedPackage stream.");
        }

        EncryptionParameters parameters =
            ParseEncryptionInfo(
                encryptionInfo);

        byte[] passwordHash =
            DerivePasswordHash(
                parameters.PasswordSalt,
                password,
                parameters.SpinCount);

        byte[] verifierInputKey =
            DeriveEncryptionKey(
                passwordHash,
                BlockKeyVerifierHashInput);

        byte[] verifierHashValueKey =
            DeriveEncryptionKey(
                passwordHash,
                BlockKeyEncryptedVerifierHashValue);

        byte[] encryptedKeyValueKey =
            DeriveEncryptionKey(
                passwordHash,
                BlockKeyEncryptedKeyValue);

        byte[] verifierInput =
            DecryptAesCbcNoPadding(
                parameters.EncryptedVerifierHashInput,
                verifierInputKey,
                parameters.PasswordSalt);

        byte[] expectedVerifierHash =
            SHA512.HashData(
                verifierInput);

        byte[] actualVerifierHash =
            DecryptAesCbcNoPadding(
                parameters.EncryptedVerifierHashValue,
                verifierHashValueKey,
                parameters.PasswordSalt);

        if (!CryptographicOperations.FixedTimeEquals(
                expectedVerifierHash,
                actualVerifierHash))
        {
            throw new CryptographicException(
                "Invalid password.");
        }

        byte[] secretKeyPadded =
            DecryptAesCbcNoPadding(
                parameters.EncryptedKeyValue,
                encryptedKeyValueKey,
                parameters.PasswordSalt);

        byte[] secretKey =
            new byte[KeySize];

        Buffer.BlockCopy(
            secretKeyPadded,
            0,
            secretKey,
            0,
            KeySize);

        VerifyIntegrity(
            parameters,
            encryptedPackage,
            secretKey);

        return DecryptEncryptedPackage(
            encryptedPackage,
            secretKey,
            parameters.KeyDataSalt);
    }

    private static byte[] DecryptEncryptedPackage(
        byte[] encryptedPackage,
        byte[] secretKey,
        byte[] keyDataSalt)
    {
        ulong streamSize =
            ReadUInt64(
                encryptedPackage,
                0);

        if (streamSize > int.MaxValue)
        {
            throw new NotSupportedException(
                "EncryptedPackage larger than 2 GB is not supported.");
        }

        int originalLength =
            checked((int)streamSize);

        if (originalLength == 0)
        {
            return Array.Empty<byte>();
        }

        using MemoryStream output =
            new MemoryStream(originalLength);

        int encryptedOffset = 8;
        int remaining = originalLength;
        int segmentNumber = 0;

        while (remaining > 0)
        {
            int plaintextCount =
                Math.Min(
                    SegmentSize,
                    remaining);

            int encryptedCount =
                ((plaintextCount + BlockSize - 1) /
                 BlockSize) *
                BlockSize;

            if (encryptedOffset + encryptedCount >
                encryptedPackage.Length)
            {
                throw new InvalidDataException(
                    "EncryptedPackage is truncated.");
            }

            byte[] encryptedSegment =
                new byte[encryptedCount];

            Buffer.BlockCopy(
                encryptedPackage,
                encryptedOffset,
                encryptedSegment,
                0,
                encryptedCount);

            byte[] iv =
                GeneratePackageIv(
                    keyDataSalt,
                    segmentNumber);

            byte[] decrypted =
                DecryptAesCbcNoPadding(
                    encryptedSegment,
                    secretKey,
                    iv);

            output.Write(
                decrypted,
                0,
                plaintextCount);

            encryptedOffset += encryptedCount;
            remaining -= plaintextCount;
            segmentNumber++;
        }

        if (encryptedOffset != encryptedPackage.Length)
        {
            throw new InvalidDataException(
                "EncryptedPackage contains unexpected trailing data.");
        }

        return output.ToArray();
    }

    private static void VerifyIntegrity(
        EncryptionParameters parameters,
        byte[] encryptedPackage,
        byte[] secretKey)
    {
        if (parameters.EncryptedHmacKey == null ||
            parameters.EncryptedHmacValue == null)
        {
            throw new InvalidDataException(
                "Agile EncryptionInfo is missing DataIntegrity values.");
        }

        byte[] iv1 =
            GenerateIntegrityIv(
                parameters.KeyDataSalt,
                BlockKeyDataIntegrity1);

        byte[] iv2 =
            GenerateIntegrityIv(
                parameters.KeyDataSalt,
                BlockKeyDataIntegrity2);

        byte[] hmacKey =
            DecryptAesCbcNoPadding(
                parameters.EncryptedHmacKey,
                secretKey,
                iv1);

        byte[] expectedHmac =
            DecryptAesCbcNoPadding(
                parameters.EncryptedHmacValue,
                secretKey,
                iv2);

        byte[] actualHmac;

        using (HMACSHA512 hmac =
               new HMACSHA512(hmacKey))
        {
            actualHmac =
                hmac.ComputeHash(
                    encryptedPackage);
        }

        if (!CryptographicOperations.FixedTimeEquals(
                expectedHmac,
                actualHmac))
        {
            throw new CryptographicException(
                "Encrypted package integrity verification failed.");
        }
    }

    private static EncryptionParameters ParseEncryptionInfo(
        byte[] encryptionInfo)
    {
        ushort major =
            ReadUInt16(
                encryptionInfo,
                0);

        ushort minor =
            ReadUInt16(
                encryptionInfo,
                2);

        uint flags =
            ReadUInt32(
                encryptionInfo,
                4);

        if (major != 4 || minor != 4)
        {
            throw new NotSupportedException(
                $"Unsupported EncryptionInfo version {major}.{minor}.");
        }

        if ((flags & 0x40) == 0)
        {
            throw new NotSupportedException(
                "EncryptionInfo does not contain Agile encryption.");
        }

        string xml =
            Encoding.UTF8.GetString(
                encryptionInfo,
                8,
                encryptionInfo.Length - 8);

        XDocument document =
            XDocument.Parse(xml);

        XNamespace encryptionNamespace =
            "http://schemas.microsoft.com/office/2006/encryption";

        XNamespace passwordNamespace =
            "http://schemas.microsoft.com/office/2006/keyEncryptor/password";

        XElement? encryption =
            document.Root;

        if (encryption == null)
        {
            throw new InvalidDataException(
                "Missing encryption element.");
        }

        XElement? keyData =
            encryption.Element(
                encryptionNamespace + "keyData");

        XElement? dataIntegrity =
            encryption.Element(
                encryptionNamespace + "dataIntegrity");

        XElement? encryptedKey =
            encryption
                .Element(
                    encryptionNamespace + "keyEncryptors")
                ?.Element(
                    encryptionNamespace + "keyEncryptor")
                ?.Element(
                    passwordNamespace + "encryptedKey");

        if (keyData == null || encryptedKey == null)
        {
            throw new InvalidDataException(
                "Invalid Agile EncryptionInfo.");
        }

        byte[] keyDataSalt =
            FromBase64Attribute(
                keyData,
                "saltValue");

        byte[] passwordSalt =
            FromBase64Attribute(
                encryptedKey,
                "saltValue");

        byte[] encryptedVerifierHashInput =
            FromBase64Attribute(
                encryptedKey,
                "encryptedVerifierHashInput");

        byte[] encryptedVerifierHashValue =
            FromBase64Attribute(
                encryptedKey,
                "encryptedVerifierHashValue");

        byte[] encryptedKeyValue =
            FromBase64Attribute(
                encryptedKey,
                "encryptedKeyValue");

        byte[]? encryptedHmacKey = null;
        byte[]? encryptedHmacValue = null;

        if (dataIntegrity != null)
        {
            encryptedHmacKey =
                FromBase64Attribute(
                    dataIntegrity,
                    "encryptedHmacKey");

            encryptedHmacValue =
                FromBase64Attribute(
                    dataIntegrity,
                    "encryptedHmacValue");
        }

        int spinCount =
            GetRequiredIntAttribute(
                encryptedKey,
                "spinCount");

        return new EncryptionParameters
        {
            PasswordSalt =
                passwordSalt,

            KeyDataSalt =
                keyDataSalt,

            SpinCount =
                spinCount,

            EncryptedVerifierHashInput =
                encryptedVerifierHashInput,

            EncryptedVerifierHashValue =
                encryptedVerifierHashValue,

            EncryptedKeyValue =
                encryptedKeyValue,

            EncryptedHmacKey =
                encryptedHmacKey,

            EncryptedHmacValue =
                encryptedHmacValue
        };
    }

    private static byte[] FromBase64Attribute(
        XElement element,
        string name)
    {
        XAttribute? attribute =
            element.Attribute(name);

        if (attribute == null ||
            string.IsNullOrWhiteSpace(attribute.Value))
        {
            throw new InvalidDataException(
                $"Missing EncryptionInfo attribute '{name}'.");
        }

        try
        {
            return Convert.FromBase64String(
                attribute.Value);
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException(
                $"Invalid base64 value for '{name}'.",
                ex);
        }
    }

    private static int GetRequiredIntAttribute(
        XElement element,
        string name)
    {
        XAttribute? attribute =
            element.Attribute(name);

        if (attribute == null ||
            !int.TryParse(
                attribute.Value,
                out int value))
        {
            throw new InvalidDataException(
                $"Invalid or missing integer attribute '{name}'.");
        }

        return value;
    }

    // ========================================================================
    // AES
    // ========================================================================

    private static byte[] EncryptAesCbcNoPadding(
        byte[] plaintext,
        byte[] key,
        byte[] iv)
    {
        if (plaintext.Length % BlockSize != 0)
        {
            throw new ArgumentException(
                "Plaintext must be a multiple of 16 bytes.");
        }

        using Aes aes =
            Aes.Create();

        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        aes.Key = key;
        aes.IV = iv;

        using ICryptoTransform encryptor =
            aes.CreateEncryptor();

        return encryptor.TransformFinalBlock(
            plaintext,
            0,
            plaintext.Length);
    }

    private static byte[] EncryptAesCbcPaddedZero(
        byte[] plaintext,
        byte[] key,
        byte[] iv)
    {
        int paddedLength =
            ((plaintext.Length + BlockSize - 1)
             / BlockSize)
            * BlockSize;

        byte[] padded =
            new byte[paddedLength];

        Buffer.BlockCopy(
            plaintext,
            0,
            padded,
            0,
            plaintext.Length);

        return EncryptAesCbcNoPadding(
            padded,
            key,
            iv);
    }

    private static byte[] DecryptAesCbcNoPadding(
        byte[] ciphertext,
        byte[] key,
        byte[] iv)
    {
        if (ciphertext.Length == 0 ||
            ciphertext.Length % BlockSize != 0)
        {
            throw new CryptographicException(
                "Ciphertext length is invalid.");
        }

        using Aes aes =
            Aes.Create();

        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        aes.Key = key;
        aes.IV = iv;

        using ICryptoTransform decryptor =
            aes.CreateDecryptor();

        return decryptor.TransformFinalBlock(
            ciphertext,
            0,
            ciphertext.Length);
    }

    // ========================================================================
    // BINARY HELPERS
    // ========================================================================

    private static byte[] UInt32LittleEndian(
        uint value)
    {
        return new[]
        {
            (byte)value,
            (byte)(value >> 8),
            (byte)(value >> 16),
            (byte)(value >> 24)
        };
    }

    private static byte[] Combine(
        params byte[][] arrays)
    {
        int totalLength = 0;

        foreach (byte[] array in arrays)
        {
            totalLength += array.Length;
        }

        byte[] result =
            new byte[totalLength];

        int offset = 0;

        foreach (byte[] array in arrays)
        {
            Buffer.BlockCopy(
                array,
                0,
                result,
                offset,
                array.Length);

            offset += array.Length;
        }

        return result;
    }

    private static ushort ReadUInt16(
        byte[] data,
        int offset)
    {
        return (ushort)(
            data[offset] |
            (data[offset + 1] << 8));
    }

    private static uint ReadUInt32(
        byte[] data,
        int offset)
    {
        return
            (uint)data[offset] |
            ((uint)data[offset + 1] << 8) |
            ((uint)data[offset + 2] << 16) |
            ((uint)data[offset + 3] << 24);
    }

    private static ulong ReadUInt64(
        byte[] data,
        int offset)
    {
        ulong value = 0;

        for (int i = 0; i < 8; i++)
        {
            value |=
                (ulong)data[offset + i] <<
                (8 * i);
        }

        return value;
    }

    private static void WriteUInt16(
        Stream stream,
        ushort value)
    {
        stream.WriteByte(
            (byte)value);

        stream.WriteByte(
            (byte)(value >> 8));
    }

    private static void WriteUInt32(
        Stream stream,
        uint value)
    {
        stream.WriteByte(
            (byte)value);

        stream.WriteByte(
            (byte)(value >> 8));

        stream.WriteByte(
            (byte)(value >> 16));

        stream.WriteByte(
            (byte)(value >> 24));
    }

    private static void WriteUInt64(
        Stream stream,
        ulong value)
    {
        for (int i = 0; i < 8; i++)
        {
            stream.WriteByte(
                (byte)(value >> (8 * i)));
        }
    }

    // ========================================================================
    // DECRYPTION PARAMETERS
    // ========================================================================

    private sealed class EncryptionParameters
    {
        public required byte[] PasswordSalt { get; init; }
        public required byte[] KeyDataSalt { get; init; }
        public required byte[] EncryptedVerifierHashInput { get; init; }
        public required byte[] EncryptedVerifierHashValue { get; init; }
        public required byte[] EncryptedKeyValue { get; init; }
        public byte[]? EncryptedHmacKey { get; init; }
        public byte[]? EncryptedHmacValue { get; init; }
        public required int SpinCount { get; init; }
    }
}


// ============================================================================
// OLE COMPOUND FILE
// ============================================================================

internal static class OleCompoundFile
{
    private const uint STGM_DIRECT =
        0x00000000;

    private const uint STGM_WRITE =
        0x00000001;

    private const uint STGM_READ =
        0x00000000;

    private const uint STGM_READWRITE =
        0x00000002;

    private const uint STGM_SHARE_EXCLUSIVE =
        0x00000010;

    private const uint STGM_CREATE =
        0x00001000;

    private const uint STGC_DEFAULT =
        0x00000000;

    private const uint CREATE_STREAM_MODE =
        STGM_CREATE |
        STGM_WRITE |
        STGM_DIRECT |
        STGM_SHARE_EXCLUSIVE;

    private const uint CREATE_STORAGE_MODE =
        STGM_CREATE |
        STGM_READWRITE |
        STGM_DIRECT |
        STGM_SHARE_EXCLUSIVE;

    private const uint ROOT_MODE =
        STGM_CREATE |
        STGM_READWRITE |
        STGM_DIRECT |
        STGM_SHARE_EXCLUSIVE;

    private const uint READ_STREAM_MODE =
        STGM_READ |
        STGM_DIRECT |
        STGM_SHARE_EXCLUSIVE;

    [DllImport(
        "ole32.dll",
        CharSet = CharSet.Unicode,
        ExactSpelling = true)]
    private static extern int StgCreateDocfile(
        string pwcsName,
        uint grfMode,
        uint reserved,
        out IStorage ppstgOpen);

    [DllImport(
        "ole32.dll",
        CharSet = CharSet.Unicode,
        ExactSpelling = true)]
    private static extern int StgOpenStorage(
        string pwcsName,
        IStorage? pstgPriority,
        uint grfMode,
        IntPtr snbExclude,
        uint reserved,
        out IStorage ppstgOpen);

    // ========================================================================
    // CREATE COMPOUND FILE
    // ========================================================================

    public static void Create(
        byte[] encryptionInfo,
        byte[] encryptedPackage,
        string outputFile)
    {
        string directory =
            Path.GetDirectoryName(
                Path.GetFullPath(outputFile))
            ?? Directory.GetCurrentDirectory();

        Directory.CreateDirectory(
            directory);

        string tempFile =
            Path.Combine(
                directory,
                Guid.NewGuid().ToString("N") +
                ".ole");

        IStorage? root = null;

        try
        {
            int hr =
                StgCreateDocfile(
                    tempFile,
                    ROOT_MODE,
                    0,
                    out root);

            Marshal.ThrowExceptionForHR(
                hr);

            CreateDataSpaces(
                root);

            WriteStream(
                root,
                "EncryptionInfo",
                encryptionInfo);

            WriteStream(
                root,
                "EncryptedPackage",
                encryptedPackage);

            int commitResult =
                root.Commit(
                    STGC_DEFAULT);

            Marshal.ThrowExceptionForHR(
                commitResult);
        }
        finally
        {
            if (root != null)
            {
                Marshal.FinalReleaseComObject(
                    root);
            }

            GC.Collect();
            GC.WaitForPendingFinalizers();

            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        MoveWithRetry(
            tempFile,
            outputFile);
    }

    // ========================================================================
    // READ COMPOUND FILE
    // ========================================================================

    public static void Read(
        string filePath,
        out byte[] encryptionInfo,
        out byte[] encryptedPackage)
    {
        IStorage? storage = null;

        try
        {
            int hr =
                StgOpenStorage(
                    filePath,
                    null,
                    READ_STREAM_MODE,
                    IntPtr.Zero,
                    0,
                    out storage);

            Marshal.ThrowExceptionForHR(
                hr);

            encryptionInfo =
                ReadStream(
                    storage,
                    "EncryptionInfo");

            encryptedPackage =
                ReadStream(
                    storage,
                    "EncryptedPackage");
        }
        finally
        {
            ReleaseComObject(
                storage);
        }
    }

    private static byte[] ReadStream(
        IStorage storage,
        string name)
    {
        IStream? stream = null;

        try
        {
            int hr =
                storage.OpenStream(
                    name,
                    IntPtr.Zero,
                    READ_STREAM_MODE,
                    0,
                    out stream);

            Marshal.ThrowExceptionForHR(
                hr);

            stream.Stat(
                out STATSTG stat,
                1 /* STATFLAG_NONAME */);

            ulong size =
                stat.cbSize;

            if (size > int.MaxValue)
            {
                throw new NotSupportedException(
                    $"OLE stream '{name}' is larger than 2 GB.");
            }

            byte[] result =
                new byte[(int)size];

            int offset = 0;

            while (offset < result.Length)
            {
                int remaining =
                    result.Length - offset;

                int chunk =
                    Math.Min(
                        remaining,
                        1024 * 1024);

                byte[] buffer =
                    new byte[chunk];

                IntPtr pcbRead =
                    Marshal.AllocHGlobal(
                        sizeof(int));

                try
                {
                    hr =
                        stream.Read(
                            buffer,
                            chunk,
                            pcbRead);

                    Marshal.ThrowExceptionForHR(
                        hr);

                    int bytesRead =
                        Marshal.ReadInt32(
                            pcbRead);

                    if (bytesRead <= 0)
                    {
                        throw new EndOfStreamException(
                            $"Unexpected end of OLE stream '{name}'.");
                    }

                    Buffer.BlockCopy(
                        buffer,
                        0,
                        result,
                        offset,
                        bytesRead);

                    offset += bytesRead;
                }
                finally
                {
                    Marshal.FreeHGlobal(
                        pcbRead);
                }
            }

            return result;
        }
        finally
        {
            ReleaseComObject(
                stream);
        }
    }

    // ========================================================================
    // DATASPACES
    // ========================================================================

    private static void CreateDataSpaces(
        IStorage root)
    {
        IStorage? dataSpaces = null;
        IStorage? dataSpaceInfo = null;
        IStorage? transformInfo = null;
        IStorage? strongEncryptionTransform = null;

        try
        {
            // \x06DataSpaces
            dataSpaces =
                CreateStorage(
                    root,
                    "\x06DataSpaces");

            // \x06DataSpaces/Version
            WriteStream(
                dataSpaces,
                "Version",
                CreateVersionStream());

            // \x06DataSpaces/DataSpaceMap
            WriteStream(
                dataSpaces,
                "DataSpaceMap",
                CreateDataSpaceMap());

            // \x06DataSpaces/DataSpaceInfo
            dataSpaceInfo =
                CreateStorage(
                    dataSpaces,
                    "DataSpaceInfo");

            // DataSpaceInfo/StrongEncryptionDataSpace
            WriteStream(
                dataSpaceInfo,
                "StrongEncryptionDataSpace",
                CreateDataSpaceDefinition());

            // \x06DataSpaces/TransformInfo
            transformInfo =
                CreateStorage(
                    dataSpaces,
                    "TransformInfo");

            // TransformInfo/StrongEncryptionTransform
            strongEncryptionTransform =
                CreateStorage(
                    transformInfo,
                    "StrongEncryptionTransform");

            // TransformInfo/StrongEncryptionTransform/\x06Primary
            WriteStream(
                strongEncryptionTransform,
                "\x06Primary",
                CreateTransformInfo());

            Commit(
                strongEncryptionTransform);

            Commit(
                transformInfo);

            Commit(
                dataSpaceInfo);

            Commit(
                dataSpaces);
        }
        finally
        {
            ReleaseComObject(
                strongEncryptionTransform);

            ReleaseComObject(
                transformInfo);

            ReleaseComObject(
                dataSpaceInfo);

            ReleaseComObject(
                dataSpaces);
        }
    }

    // ========================================================================
    // VERSION
    // ========================================================================

    private static byte[] CreateVersionStream()
    {
        using MemoryStream ms =
            new MemoryStream();

        WriteUnicodeLpP4(
            ms,
            "Microsoft.Container.DataSpaces");

        WriteVersion(
            ms,
            1,
            0);

        WriteVersion(
            ms,
            1,
            0);

        WriteVersion(
            ms,
            1,
            0);

        return ms.ToArray();
    }

    // ========================================================================
    // DATASPACE MAP
    // ========================================================================

    private static byte[] CreateDataSpaceMap()
    {
        using MemoryStream ms =
            new MemoryStream();

        // HeaderLength
        WriteUInt32(
            ms,
            8);

        // EntryCount
        WriteUInt32(
            ms,
            1);

        using MemoryStream entry =
            new MemoryStream();

        // ReferenceComponentCount
        WriteUInt32(
            entry,
            1);

        // ReferenceComponentType: 0 = stream
        WriteUInt32(
            entry,
            0);

        // ReferenceComponentName
        WriteUnicodeLpP4(
            entry,
            "EncryptedPackage");

        // DataSpaceName
        WriteUnicodeLpP4(
            entry,
            "StrongEncryptionDataSpace");

        byte[] entryBytes =
            entry.ToArray();

        // EntryLength
        WriteUInt32(
            ms,
            checked(
                (uint)(4 + entryBytes.Length)));

        ms.Write(
            entryBytes,
            0,
            entryBytes.Length);

        return ms.ToArray();
    }

    // ========================================================================
    // DATASPACE DEFINITION
    // ========================================================================

    private static byte[] CreateDataSpaceDefinition()
    {
        using MemoryStream ms =
            new MemoryStream();

        // HeaderLength
        WriteUInt32(
            ms,
            8);

        // TransformReferenceCount
        WriteUInt32(
            ms,
            1);

        // TransformReference
        WriteUnicodeLpP4(
            ms,
            "StrongEncryptionTransform");

        return ms.ToArray();
    }

    // ========================================================================
    // TRANSFORM INFO
    // ========================================================================

    private static byte[] CreateTransformInfo()
    {
        using MemoryStream ms =
            new MemoryStream();

        using MemoryStream header =
            new MemoryStream();

        // TransformType
        WriteUInt32(
            header,
            1);

        // TransformID
        WriteUnicodeLpP4(
            header,
            "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}");

        byte[] headerBytes =
            header.ToArray();

        // TransformLength
        WriteUInt32(
            ms,
            checked(
                (uint)(4 + headerBytes.Length)));

        ms.Write(
            headerBytes,
            0,
            headerBytes.Length);

        // TransformName
        WriteUnicodeLpP4(
            ms,
            "Microsoft.Container.EncryptionTransform");

        // ReaderVersion
        WriteVersion(
            ms,
            1,
            0);

        // UpdaterVersion
        WriteVersion(
            ms,
            1,
            0);

        // WriterVersion
        WriteVersion(
            ms,
            1,
            0);

        // EncryptionName
        WriteUInt32(
            ms,
            0);

        // Reserved
        WriteUInt32(
            ms,
            0);

        return ms.ToArray();
    }

    // ========================================================================
    // OLE STORAGE HELPERS
    // ========================================================================

    private static IStorage CreateStorage(
        IStorage parent,
        string name)
    {
        int hr =
            parent.CreateStorage(
                name,
                CREATE_STORAGE_MODE,
                0,
                0,
                out IStorage storage);

        Marshal.ThrowExceptionForHR(
            hr);

        return storage;
    }

    private static void WriteStream(
        IStorage parent,
        string name,
        byte[] data)
    {
        IStream? stream = null;

        try
        {
            int hr =
                parent.CreateStream(
                    name,
                    CREATE_STREAM_MODE,
                    0,
                    0,
                    out stream);

            Marshal.ThrowExceptionForHR(
                hr);

            if (data.Length > 0)
            {
                hr =
                    stream.Write(
                        data,
                        data.Length,
                        IntPtr.Zero);

                Marshal.ThrowExceptionForHR(
                    hr);
            }

            hr =
                stream.Commit(
                    STGC_DEFAULT);

            Marshal.ThrowExceptionForHR(
                hr);
        }
        finally
        {
            ReleaseComObject(
                stream);
        }
    }

    private static void Commit(
        IStorage storage)
    {
        int hr =
            storage.Commit(
                STGC_DEFAULT);

        Marshal.ThrowExceptionForHR(
            hr);
    }

    // ========================================================================
    // DATASPACES BINARY HELPERS
    // ========================================================================

    private static void WriteUnicodeLpP4(
        Stream stream,
        string value)
    {
        byte[] bytes =
            Encoding.Unicode.GetBytes(
                value);

        // Length is measured in bytes.
        WriteUInt32(
            stream,
            checked((uint)bytes.Length));

        stream.Write(
            bytes,
            0,
            bytes.Length);

        int padding =
            (4 - (bytes.Length % 4)) % 4;

        for (int i = 0;
             i < padding;
             i++)
        {
            stream.WriteByte(
                0);
        }
    }

    private static void WriteVersion(
        Stream stream,
        ushort major,
        ushort minor)
    {
        WriteUInt16(
            stream,
            major);

        WriteUInt16(
            stream,
            minor);
    }

    private static void WriteUInt16(
        Stream stream,
        ushort value)
    {
        stream.WriteByte(
            (byte)value);

        stream.WriteByte(
            (byte)(value >> 8));
    }

    private static void WriteUInt32(
        Stream stream,
        uint value)
    {
        stream.WriteByte(
            (byte)value);

        stream.WriteByte(
            (byte)(value >> 8));

        stream.WriteByte(
            (byte)(value >> 16));

        stream.WriteByte(
            (byte)(value >> 24));
    }

    // ========================================================================
    // CLEANUP & RETRY
    // ========================================================================

    private static void ReleaseComObject(
        object? obj)
    {
        if (obj == null)
        {
            return;
        }

        try
        {
            Marshal.FinalReleaseComObject(
                obj);
        }
        catch
        {
        }
    }

    private static void MoveWithRetry(
        string source,
        string destination)
    {
        Exception? lastException = null;

        for (int attempt = 0;
             attempt < 10;
             attempt++)
        {
            try
            {
                if (File.Exists(destination))
                {
                    File.Delete(
                        destination);
                }

                File.Move(
                    source,
                    destination);

                return;
            }
            catch (Exception ex)
            {
                lastException = ex;

                GC.Collect();
                GC.WaitForPendingFinalizers();

                System.Threading.Thread.Sleep(
                    100);
            }
        }

        throw new IOException(
            "Unable to move generated OLE file.",
            lastException);
    }
}


// ============================================================================
// COM IStorage
// ============================================================================

[ComImport]
[Guid("0000000B-0000-0000-C000-000000000046")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IStorage
{
    [PreserveSig]
    int CreateStream(
        [MarshalAs(UnmanagedType.LPWStr)]
        string pwcsName,
        uint grfMode,
        uint reserved1,
        uint reserved2,
        out IStream ppstm);

    [PreserveSig]
    int OpenStream(
        [MarshalAs(UnmanagedType.LPWStr)]
        string pwcsName,
        IntPtr reserved1,
        uint grfMode,
        uint reserved2,
        out IStream ppstm);

    [PreserveSig]
    int CreateStorage(
        [MarshalAs(UnmanagedType.LPWStr)]
        string pwcsName,
        uint grfMode,
        uint reserved1,
        uint reserved2,
        out IStorage ppstg);

    [PreserveSig]
    int OpenStorage(
        [MarshalAs(UnmanagedType.LPWStr)]
        string pwcsName,
        IStorage? pStgPriority,
        uint grfMode,
        IntPtr snbExclude,
        uint reserved,
        out IStorage ppstg);

    [PreserveSig]
    int CopyTo(
        uint ciidExclude,
        IntPtr rgiidExclude,
        IntPtr snbExclude,
        IStorage pstgDest);

    [PreserveSig]
    int MoveElementTo(
        [MarshalAs(UnmanagedType.LPWStr)]
        string pwcsName,
        IStorage pstgDest,
        [MarshalAs(UnmanagedType.LPWStr)]
        string pwcsNewName,
        uint grfFlags);

    [PreserveSig]
    int Commit(
        uint grfCommitFlags);

    [PreserveSig]
    int Revert();

    [PreserveSig]
    int EnumElements(
        uint reserved1,
        IntPtr reserved2,
        uint reserved3,
        out IntPtr ppenum);

    [PreserveSig]
    int DestroyElement(
        [MarshalAs(UnmanagedType.LPWStr)]
        string pwcsName);

    [PreserveSig]
    int RenameElement(
        [MarshalAs(UnmanagedType.LPWStr)]
        string pwcsOldName,
        [MarshalAs(UnmanagedType.LPWStr)]
        string pwcsNewName);

    [PreserveSig]
    int SetElementTimes(
        [MarshalAs(UnmanagedType.LPWStr)]
        string pwcsName,
        IntPtr pctime,
        IntPtr patime,
        IntPtr pmtime);

    [PreserveSig]
    int SetClass(
        ref Guid clsid);

    [PreserveSig]
    int SetStateBits(
        uint grfStateBits,
        uint grfMask);

    [PreserveSig]
    int Stat(
        out STATSTG pstatstg,
        uint grfStatFlag);
}


// ============================================================================
// COM IStream
// ============================================================================

[ComImport]
[Guid("0000000C-0000-0000-C000-000000000046")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IStream
{
    [PreserveSig]
    int Read(
        [Out]
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)]
        byte[] pv,
        int cb,
        IntPtr pcbRead);

    [PreserveSig]
    int Write(
        [In]
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)]
        byte[] pv,
        int cb,
        IntPtr pcbWritten);

    [PreserveSig]
    int Seek(
        long dlibMove,
        int dwOrigin,
        IntPtr plibNewPosition);

    [PreserveSig]
    int SetSize(
        long libNewSize);

    [PreserveSig]
    int CopyTo(
        IStream pstm,
        long cb,
        IntPtr pcbRead,
        IntPtr pcbWritten);

    [PreserveSig]
    int Commit(
        uint grfCommitFlags);

    [PreserveSig]
    int Revert();

    [PreserveSig]
    int LockRegion(
        long libOffset,
        long cb,
        uint dwLockType);

    [PreserveSig]
    int UnlockRegion(
        long libOffset,
        long cb,
        uint dwLockType);

    [PreserveSig]
    int Stat(
        out STATSTG pstatstg,
        uint grfStatFlag);

    [PreserveSig]
    int Clone(
        out IStream ppstm);
}


// ============================================================================
// STATSTG
// ============================================================================

[StructLayout(LayoutKind.Sequential)]
internal struct STATSTG
{
    public IntPtr pwcsName;
    public uint type;
    public ulong cbSize;

    public System.Runtime.InteropServices.ComTypes.FILETIME mtime;
    public System.Runtime.InteropServices.ComTypes.FILETIME ctime;
    public System.Runtime.InteropServices.ComTypes.FILETIME atime;

    public uint grfMode;
    public uint grfLocksSupported;

    public Guid clsid;

    public uint grfStateBits;
    public uint reserved;
}