using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace XlsxCrypt;

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

    // ============================================================
    // PUBLIC ENCRYPTION API
    // ============================================================

    public static void EncryptFile(
        string inputFile,
        string outputFile,
        string password)
    {
        if (string.IsNullOrWhiteSpace(inputFile))
            throw new ArgumentException(
                "Input file cannot be empty.",
                nameof(inputFile));

        if (string.IsNullOrWhiteSpace(outputFile))
            throw new ArgumentException(
                "Output file cannot be empty.",
                nameof(outputFile));

        if (string.IsNullOrEmpty(password))
            throw new ArgumentException(
                "Password cannot be empty.",
                nameof(password));

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
        if (string.IsNullOrWhiteSpace(inputFile))
            throw new ArgumentException(
                "Input file cannot be empty.",
                nameof(inputFile));

        if (string.IsNullOrWhiteSpace(outputFile))
            throw new ArgumentException(
                "Output file cannot be empty.",
                nameof(outputFile));

        if (string.IsNullOrEmpty(password))
            throw new ArgumentException(
                "Password cannot be empty.",
                nameof(password));

        OleCompoundFile.Read(
            inputFile,
            out byte[] encryptionInfo,
            out byte[] encryptedPackage);

        byte[] originalPackage =
            DecryptPackage(
                encryptionInfo,
                encryptedPackage,
                password);

        File.WriteAllBytes(
            outputFile,
            originalPackage);
    }

    // ============================================================
    // CREATION
    // ============================================================

    public static NativeExcelEncryption Create(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException(
                "Password cannot be empty.",
                nameof(password));

        byte[] passwordSalt =
            RandomNumberGenerator.GetBytes(SaltSize);

        byte[] keyDataSalt =
            RandomNumberGenerator.GetBytes(SaltSize);

        byte[] secretKey =
            RandomNumberGenerator.GetBytes(KeySize);

        byte[] verifierHashInput =
            RandomNumberGenerator.GetBytes(SaltSize);

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

    // ============================================================
    // PASSWORD KEY DERIVATION
    // ============================================================

    private byte[] DerivePasswordHash()
    {
        byte[] passwordBytes =
            Encoding.Unicode.GetBytes(_password);

        byte[] initial =
            Combine(
                _passwordSalt,
                passwordBytes);

        byte[] hash =
            SHA512.HashData(initial);

        for (uint i = 0; i < SpinCount; i++)
        {
            byte[] counter =
                UInt32LittleEndian(i);

            hash =
                SHA512.HashData(
                    Combine(
                        counter,
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

    // ============================================================
    // PASSWORD ENCRYPTION VALUES
    // ============================================================

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

        _encryptedVerifierHashInput =
            EncryptAesCbcNoPadding(
                _verifierHashInput,
                verifierInputKey,
                _passwordSalt);

        byte[] verifierHash =
            SHA512.HashData(
                _verifierHashInput);

        _encryptedVerifierHashValue =
            EncryptAesCbcPaddedZero(
                verifierHash,
                verifierHashValueKey,
                _passwordSalt);

        _encryptedKeyValue =
            EncryptAesCbcPaddedZero(
                _secretKey,
                encryptedKeyValueKey,
                _passwordSalt);
    }

    // ============================================================
    // PACKAGE ENCRYPTION
    // ============================================================

    public byte[] EncryptPackage(byte[] originalPackage)
    {
        using MemoryStream output =
            new MemoryStream();

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

    private byte[] GeneratePackageIv(
        int segmentNumber)
    {
        byte[] segment =
            UInt32LittleEndian(
                unchecked((uint)segmentNumber));

        byte[] hash =
            SHA512.HashData(
                Combine(
                    _keyDataSalt,
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

    // ============================================================
    // DATA INTEGRITY
    // ============================================================

    public void GenerateIntegrity(
        byte[] encryptedPackage)
    {
        /*
         * Agile encryption specifies that the random HMAC key
         * has the same size as KeyData.saltSize.
         *
         * saltSize = 16
         *
         * The HMAC output itself is SHA-512 = 64 bytes.
         */
        byte[] hmacKey =
            RandomNumberGenerator.GetBytes(
                SaltSize);

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
                BlockKeyDataIntegrity1);

        byte[] iv2 =
            GenerateIntegrityIv(
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

    private byte[] GenerateIntegrityIv(
        byte[] blockKey)
    {
        byte[] hash =
            SHA512.HashData(
                Combine(
                    _keyDataSalt,
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

    // ============================================================
    // ENCRYPTION INFO
    // ============================================================

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
            "<encryption " +
            "xmlns=\"http://schemas.microsoft.com/office/2006/encryption\" " +
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
            Encoding.UTF8.GetBytes(xml);

        using MemoryStream ms =
            new MemoryStream();

        /*
         * Version:
         *
         * Major = 4
         * Minor = 4
         * Flags = 0x40
         */
        WriteUInt16(ms, 4);
        WriteUInt16(ms, 4);
        WriteUInt32(ms, 0x40);

        ms.Write(
            xmlBytes,
            0,
            xmlBytes.Length);

        return ms.ToArray();
    }

    // ============================================================
    // DECRYPTION
    // ============================================================

    public static byte[] DecryptPackage(
        byte[] encryptionInfo,
        byte[] encryptedPackage,
        string password)
    {
        if (encryptionInfo == null ||
            encryptionInfo.Length < 8)
        {
            throw new InvalidDataException(
                "Invalid EncryptionInfo stream.");
        }

        if (encryptedPackage == null ||
            encryptedPackage.Length < 8)
        {
            throw new InvalidDataException(
                "Invalid EncryptedPackage stream.");
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException(
                "Password cannot be empty.",
                nameof(password));
        }

        EncryptionParameters parameters =
            ParseEncryptionInfo(
                encryptionInfo);

        byte[] passwordBytes =
            Encoding.Unicode.GetBytes(password);

        byte[] passwordHash =
            DerivePasswordHashForDecryption(
                parameters.PasswordSalt,
                passwordBytes,
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

        byte[] secretKey =
            DecryptAesCbcNoPadding(
                parameters.EncryptedKeyValue,
                encryptedKeyValueKey,
                parameters.PasswordSalt);

        if (secretKey.Length != KeySize)
        {
            throw new CryptographicException(
                "Invalid encryption key.");
        }

        VerifyIntegrity(
            parameters,
            encryptedPackage,
            secretKey);

        return DecryptEncryptedPackage(
            encryptedPackage,
            secretKey,
            parameters.KeyDataSalt);
    }

    private static byte[] DerivePasswordHashForDecryption(
        byte[] salt,
        byte[] passwordBytes,
        int spinCount)
    {
        byte[] initial =
            Combine(
                salt,
                passwordBytes);

        byte[] hash =
            SHA512.HashData(
                initial);

        for (uint i = 0;
             i < spinCount;
             i++)
        {
            byte[] counter =
                UInt32LittleEndian(i);

            hash =
                SHA512.HashData(
                    Combine(
                        counter,
                        hash));
        }

        return hash;
    }

    // ============================================================
    // DECRYPT ENCRYPTED PACKAGE
    // ============================================================

    private static byte[] DecryptEncryptedPackage(
        byte[] encryptedPackage,
        byte[] secretKey,
        byte[] keyDataSalt)
    {
        if (encryptedPackage.Length < 8)
        {
            throw new InvalidDataException(
                "EncryptedPackage is too small.");
        }

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
            return Array.Empty<byte>();

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
                GeneratePackageIvForDecryption(
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

    private static byte[] GeneratePackageIvForDecryption(
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

    // ============================================================
    // INTEGRITY VERIFICATION
    // ============================================================

    private static void VerifyIntegrity(
        EncryptionParameters parameters,
        byte[] encryptedPackage,
        byte[] secretKey)
    {
        if (parameters.EncryptedHmacKey == null ||
            parameters.EncryptedHmacValue == null)
        {
            return;
        }

        byte[] iv1 =
            GenerateIntegrityIvForDecryption(
                parameters.KeyDataSalt,
                BlockKeyDataIntegrity1);

        byte[] iv2 =
            GenerateIntegrityIvForDecryption(
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

    private static byte[] GenerateIntegrityIvForDecryption(
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

    // ============================================================
    // ENCRYPTION INFO PARSING
    // ============================================================

    private static EncryptionParameters ParseEncryptionInfo(
        byte[] encryptionInfo)
    {
        if (encryptionInfo.Length < 8)
        {
            throw new InvalidDataException(
                "Invalid EncryptionInfo.");
        }

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

        if (keyData == null ||
            encryptedKey == null)
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

        int keyBits =
            GetRequiredIntAttribute(
                encryptedKey,
                "keyBits");

        int saltSize =
            GetRequiredIntAttribute(
                encryptedKey,
                "saltSize");

        int blockSize =
            GetRequiredIntAttribute(
                encryptedKey,
                "blockSize");

        int hashSize =
            GetRequiredIntAttribute(
                encryptedKey,
                "hashSize");

        if (saltSize != SaltSize)
        {
            throw new NotSupportedException(
                $"Unsupported salt size: {saltSize}.");
        }

        if (blockSize != BlockSize)
        {
            throw new NotSupportedException(
                $"Unsupported block size: {blockSize}.");
        }

        if (keyBits != 256)
        {
            throw new NotSupportedException(
                $"Unsupported key size: {keyBits}.");
        }

        if (hashSize != HashSize)
        {
            throw new NotSupportedException(
                $"Unsupported hash size: {hashSize}.");
        }

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

    // ============================================================
    // AES
    // ============================================================

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

        if (key.Length != KeySize)
        {
            throw new ArgumentException(
                "AES key must be 32 bytes.",
                nameof(key));
        }

        if (iv.Length != BlockSize)
        {
            throw new ArgumentException(
                "AES IV must be 16 bytes.",
                nameof(iv));
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
            ((plaintext.Length + BlockSize - 1) /
             BlockSize) *
            BlockSize;

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

        if (key.Length != KeySize)
        {
            throw new CryptographicException(
                "AES key must be 32 bytes.");
        }

        if (iv.Length != BlockSize)
        {
            throw new CryptographicException(
                "AES IV must be 16 bytes.");
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

    // ============================================================
    // BYTE HELPERS
    // ============================================================

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
            totalLength += array.Length;

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

    // ============================================================
    // DECRYPTION PARAMETERS
    // ============================================================

    private sealed class EncryptionParameters
    {
        public required byte[] PasswordSalt { get; init; }

        public required byte[] KeyDataSalt { get; init; }

        public required byte[] EncryptedVerifierHashInput
        {
            get;
            init;
        }

        public required byte[] EncryptedVerifierHashValue
        {
            get;
            init;
        }

        public required byte[] EncryptedKeyValue
        {
            get;
            init;
        }

        public byte[]? EncryptedHmacKey
        {
            get;
            init;
        }

        public byte[]? EncryptedHmacValue
        {
            get;
            init;
        }

        public required int SpinCount
        {
            get;
            init;
        }
    }

    // ============================================================
    // OLE COMPOUND FILE
    // ============================================================

    private static class OleCompoundFile
    {
        private const uint STGM_DIRECT = 0x00000000;
        private const uint STGM_WRITE = 0x00000001;
        private const uint STGM_READWRITE = 0x00000002;
        private const uint STGM_SHARE_EXCLUSIVE = 0x00000010;
        private const uint STGM_READ = 0x00000000;
        private const uint STGM_CREATE = 0x00001000;

        private const uint STGC_DEFAULT = 0x00000000;

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

        private const string DataSpaces =
            "\x0006DataSpaces";

        private const string Version =
            "Version";

        private const string DataSpaceMap =
            "DataSpaceMap";

        private const string DataSpaceInfo =
            "DataSpaceInfo";

        private const string StrongEncryptionDataSpace =
            "StrongEncryptionDataSpace";

        private const string TransformInfo =
            "TransformInfo";

        private const string StrongEncryptionTransform =
            "StrongEncryptionTransform";

        private const string Primary =
            "\x0006Primary";

        private const string EncryptionInfo =
            "EncryptionInfo";

        private const string EncryptedPackage =
            "EncryptedPackage";

        // --------------------------------------------------------
        // CREATE
        // --------------------------------------------------------

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

            IStorage? storage = null;

            try
            {
                int hr =
                    StgCreateDocfile(
                        tempFile,
                        ROOT_MODE,
                        0,
                        out storage);

                Marshal.ThrowExceptionForHR(hr);

                CreateDataSpaces(
                    storage);

                WriteStream(
                    storage,
                    EncryptionInfo,
                    encryptionInfo);

                WriteStream(
                    storage,
                    EncryptedPackage,
                    encryptedPackage);

                hr =
                    storage.Commit(
                        STGC_DEFAULT);

                Marshal.ThrowExceptionForHR(hr);
            }
            finally
            {
                if (storage != null)
                {
                    Marshal.FinalReleaseComObject(
                        storage);
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

        // --------------------------------------------------------
        // DATASPACES
        // --------------------------------------------------------

        private static void CreateDataSpaces(
            IStorage root)
        {
            IStorage? dataSpaces = null;

            try
            {
                int hr =
                    root.CreateStorage(
                        DataSpaces,
                        CREATE_STORAGE_MODE,
                        0,
                        0,
                        out dataSpaces);

                Marshal.ThrowExceptionForHR(hr);

                CreateVersionStream(
                    dataSpaces);

                CreateDataSpaceMap(
                    dataSpaces);

                CreateDataSpaceInfo(
                    dataSpaces);

                CreateTransformInfo(
                    dataSpaces);

                dataSpaces.Commit(
                    STGC_DEFAULT);
            }
            finally
            {
                if (dataSpaces != null)
                {
                    Marshal.FinalReleaseComObject(
                        dataSpaces);
                }
            }
        }

        private static void CreateVersionStream(
            IStorage dataSpaces)
        {
            using MemoryStream ms =
                new MemoryStream();

            WriteUnicodeLpP4(
                ms,
                "Microsoft.Container.DataSpaces");

            WriteUInt32(ms, 1);
            WriteUInt32(ms, 0);

            WriteUInt32(ms, 1);
            WriteUInt32(ms, 0);

            WriteUInt32(ms, 1);
            WriteUInt32(ms, 0);

            WriteStream(
                dataSpaces,
                Version,
                ms.ToArray());
        }

        private static void CreateDataSpaceMap(
            IStorage dataSpaces)
        {
            using MemoryStream ms =
                new MemoryStream();

            WriteUInt32(ms, 8);
            WriteUInt32(ms, 1);

            WriteUInt32(ms, 1);

            WriteUInt32(ms, 0);

            WriteUnicodeLpP4(
                ms,
                EncryptedPackage);

            WriteUnicodeLpP4(
                ms,
                StrongEncryptionDataSpace);

            WriteStream(
                dataSpaces,
                DataSpaceMap,
                ms.ToArray());
        }

        private static void CreateDataSpaceInfo(
            IStorage dataSpaces)
        {
            IStorage? storage = null;

            try
            {
                int hr =
                    dataSpaces.CreateStorage(
                        DataSpaceInfo,
                        CREATE_STORAGE_MODE,
                        0,
                        0,
                        out storage);

                Marshal.ThrowExceptionForHR(hr);

                using MemoryStream ms =
                    new MemoryStream();

                WriteUInt32(ms, 8);
                WriteUInt32(ms, 1);

                WriteUnicodeLpP4(
                    ms,
                    StrongEncryptionTransform);

                WriteStream(
                    storage,
                    StrongEncryptionDataSpace,
                    ms.ToArray());

                storage.Commit(
                    STGC_DEFAULT);
            }
            finally
            {
                if (storage != null)
                {
                    Marshal.FinalReleaseComObject(
                        storage);
                }
            }
        }

        private static void CreateTransformInfo(
            IStorage dataSpaces)
        {
            IStorage? transformInfo = null;
            IStorage? transform = null;

            try
            {
                int hr =
                    dataSpaces.CreateStorage(
                        TransformInfo,
                        CREATE_STORAGE_MODE,
                        0,
                        0,
                        out transformInfo);

                Marshal.ThrowExceptionForHR(hr);

                hr =
                    transformInfo.CreateStorage(
                        StrongEncryptionTransform,
                        CREATE_STORAGE_MODE,
                        0,
                        0,
                        out transform);

                Marshal.ThrowExceptionForHR(hr);

                using MemoryStream ms =
                    new MemoryStream();

                WriteUInt32(ms, 1);

                Guid transformId =
                    new Guid(
                        "FF9A3F03-56EF-4613-BDD5-5A41C1D07246");

                ms.Write(
                    transformId.ToByteArray(),
                    0,
                    16);

                WriteUnicodeLpP4(
                    ms,
                    "Microsoft.Container.EncryptionTransform");

                WriteUInt32(ms, 1);
                WriteUInt32(ms, 0);

                WriteUInt32(ms, 1);
                WriteUInt32(ms, 0);

                WriteUInt32(ms, 1);
                WriteUInt32(ms, 0);

                WriteUInt32(ms, 0);
                WriteUInt32(ms, 0);

                WriteStream(
                    transform,
                    Primary,
                    ms.ToArray());

                transform.Commit(
                    STGC_DEFAULT);

                transformInfo.Commit(
                    STGC_DEFAULT);
            }
            finally
            {
                if (transform != null)
                {
                    Marshal.FinalReleaseComObject(
                        transform);
                }

                if (transformInfo != null)
                {
                    Marshal.FinalReleaseComObject(
                        transformInfo);
                }
            }
        }

        // --------------------------------------------------------
        // OLE WRITE STREAM
        // --------------------------------------------------------

        private static void WriteStream(
            IStorage storage,
            string name,
            byte[] data)
        {
            IStream? stream = null;

            try
            {
                int hr =
                    storage.CreateStream(
                        name,
                        CREATE_STREAM_MODE,
                        0,
                        0,
                        out stream);

                Marshal.ThrowExceptionForHR(hr);

                IntPtr pcbWritten =
                    Marshal.AllocHGlobal(
                        sizeof(int));

                try
                {
                    stream.Write(
                        data,
                        data.Length,
                        pcbWritten);
                }
                finally
                {
                    Marshal.FreeHGlobal(
                        pcbWritten);
                }

                stream.Commit(
                    STGC_DEFAULT);
            }
            finally
            {
                if (stream != null)
                {
                    Marshal.FinalReleaseComObject(
                        stream);
                }
            }
        }

        // --------------------------------------------------------
        // OLE READ
        // --------------------------------------------------------

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

                Marshal.ThrowExceptionForHR(hr);

                encryptionInfo =
                    ReadStream(
                        storage,
                        EncryptionInfo);

                encryptedPackage =
                    ReadStream(
                        storage,
                        EncryptedPackage);
            }
            finally
            {
                if (storage != null)
                {
                    Marshal.FinalReleaseComObject(
                        storage);
                }
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

                Marshal.ThrowExceptionForHR(hr);

                STATSTG stat =
                    new STATSTG();

                hr =
                    stream.Stat(
                        ref stat,
                        0);

                Marshal.ThrowExceptionForHR(hr);

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
                        stream.Read(
                            buffer,
                            chunk,
                            pcbRead);

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
                if (stream != null)
                {
                    Marshal.FinalReleaseComObject(
                        stream);
                }
            }
        }

        // --------------------------------------------------------
        // OLE STRING FORMAT
        // --------------------------------------------------------

        private static void WriteUnicodeLpP4(
            Stream stream,
            string value)
        {
            byte[] bytes =
                Encoding.Unicode.GetBytes(
                    value);

            WriteUInt32(
                stream,
                (uint)bytes.Length);

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
                stream.WriteByte(0);
            }
        }

        // --------------------------------------------------------
        // FILE RETRY
        // --------------------------------------------------------

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
                        File.Delete(destination);
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

        // --------------------------------------------------------
        // NATIVE OLE API
        // --------------------------------------------------------

        [DllImport(
            "ole32.dll",
            CharSet = CharSet.Unicode)]
        private static extern int StgCreateDocfile(
            string pwcsName,
            uint grfMode,
            uint reserved,
            out IStorage ppstgOpen);

        [DllImport(
            "ole32.dll",
            CharSet = CharSet.Unicode)]
        private static extern int StgOpenStorage(
            string pwcsName,
            IStorage? pStgPriority,
            uint grfMode,
            IntPtr snbExclude,
            uint reserved,
            out IStorage ppStgOpen);

        // --------------------------------------------------------
        // COM INTERFACES
        // --------------------------------------------------------

        [ComImport]
        [Guid("0000000B-0000-0000-C000-000000000046")]
        [InterfaceType(
            ComInterfaceType.InterfaceIsIUnknown)]
        private interface IStorage
        {
            [PreserveSig]
            int CreateStream(
                [MarshalAs(
                    UnmanagedType.LPWStr)]
                string pwcsName,
                uint grfMode,
                uint reserved1,
                uint reserved2,
                out IStream ppstm);

            [PreserveSig]
            int OpenStream(
                [MarshalAs(
                    UnmanagedType.LPWStr)]
                string pwcsName,
                IntPtr reserved1,
                uint grfMode,
                uint reserved2,
                out IStream ppstm);

            [PreserveSig]
            int CreateStorage(
                [MarshalAs(
                    UnmanagedType.LPWStr)]
                string pwcsName,
                uint grfMode,
                uint reserved1,
                uint reserved2,
                out IStorage ppstg);

            [PreserveSig]
            int OpenStorage(
                [MarshalAs(
                    UnmanagedType.LPWStr)]
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
                [MarshalAs(
                    UnmanagedType.LPWStr)]
                string pwcsName,
                IStorage pstgDest,
                [MarshalAs(
                    UnmanagedType.LPWStr)]
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
                [MarshalAs(
                    UnmanagedType.LPWStr)]
                string pwcsName);

            [PreserveSig]
            int RenameElement(
                [MarshalAs(
                    UnmanagedType.LPWStr)]
                string pwcsOldName,
                [MarshalAs(
                    UnmanagedType.LPWStr)]
                string pwcsNewName);

            [PreserveSig]
            int SetElementTimes(
                [MarshalAs(
                    UnmanagedType.LPWStr)]
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
                ref STATSTG pstatstg,
                uint grfStatFlag);
        }

        [ComImport]
        [Guid("0000000C-0000-0000-C000-000000000046")]
        [InterfaceType(
            ComInterfaceType.InterfaceIsIUnknown)]
        private interface IStream
        {
            [PreserveSig]
            int Read(
                [Out]
                [MarshalAs(
                    UnmanagedType.LPArray,
                    SizeParamIndex = 1)]
                byte[] pv,
                int cb,
                IntPtr pcbRead);

            [PreserveSig]
            int Write(
                [In]
                [MarshalAs(
                    UnmanagedType.LPArray,
                    SizeParamIndex = 1)]
                byte[] pv,
                int cb,
                IntPtr pcbWritten);

            [PreserveSig]
            int Seek(
                long dlibMove,
                uint dwOrigin,
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
                ref STATSTG pstatstg,
                uint grfStatFlag);

            [PreserveSig]
            int Clone(
                out IStream ppstm);
        }

        [StructLayout(
            LayoutKind.Sequential,
            CharSet = CharSet.Unicode)]
        private struct STATSTG
        {
            [MarshalAs(
                UnmanagedType.LPWStr)]
            public string? pwcsName;

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
    }
}