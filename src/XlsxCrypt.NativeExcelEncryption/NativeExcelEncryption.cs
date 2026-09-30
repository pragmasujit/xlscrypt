using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

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

    private byte[] DerivePasswordHash()
    {
        byte[] passwordBytes =
            Encoding.Unicode.GetBytes(
                _password);

        byte[] initial =
            Combine(
                _passwordSalt,
                passwordBytes);

        byte[] hash =
            SHA512.HashData(
                initial);

        for (uint i = 0;
             i < SpinCount;
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

        // IMPORTANT:
        // This is intentionally a normal C# string rather than a
        // raw string with accidental source-code indentation.
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

        // Reserved
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

    [DllImport(
        "ole32.dll",
        CharSet = CharSet.Unicode,
        ExactSpelling = true)]
    private static extern int StgCreateDocfile(
        string pwcsName,
        uint grfMode,
        uint reserved,
        out IStorage ppstgOpen);

    // ========================================================================
    // CREATE COMPOUND FILE
    // ========================================================================

    public static byte[] Create(
        byte[] encryptionInfo,
        byte[] encryptedPackage)
    {
        string tempFile =
            Path.Combine(
                Path.GetTempPath(),
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

            Marshal.FinalReleaseComObject(
                root);

            root = null;

            GC.Collect();
            GC.WaitForPendingFinalizers();

            GC.Collect();
            GC.WaitForPendingFinalizers();

            return ReadFileWithRetry(
                tempFile);
        }
        finally
        {
            if (root != null)
            {
                try
                {
                    Marshal.FinalReleaseComObject(
                        root);
                }
                catch
                {
                }
            }

            TryDelete(
                tempFile);
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

            // TransformInfo/
            // StrongEncryptionTransform/
            // \x06Primary
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

        // ReferenceComponentType
        //
        // 0 = stream
        //
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
        //
        // Agile encryption does not specify
        // an encryption name here.
        //
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
    // CLEANUP
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

    private static byte[] ReadFileWithRetry(
        string path)
    {
        const int maxAttempts = 20;

        Exception? lastException = null;

        for (int attempt = 0;
             attempt < maxAttempts;
             attempt++)
        {
            try
            {
                return File.ReadAllBytes(
                    path);
            }
            catch (Exception ex)
            {
                lastException = ex;

                GC.Collect();
                GC.WaitForPendingFinalizers();

                Thread.Sleep(50);
            }
        }

        throw new IOException(
            "Could not read generated OLE file.",
            lastException);
    }

    private static void TryDelete(
        string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
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