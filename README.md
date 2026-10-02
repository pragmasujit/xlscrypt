# XlsCrypt.NativeExcelEncryption

Native .NET library for password-based encryption and decryption of Excel `.xlsx` workbooks.

## Features

* Native .NET implementation
* Excel-compatible workbook encryption
* Encrypt and decrypt password-protected `.xlsx` files
* Uses the Office Agile Encryption format
* AES-256-CBC encryption
* SHA-512 hashing
* Password-based key derivation
* HMAC-SHA512 data integrity verification
* No EPPlus dependency
* No ClosedXML dependency
* No Microsoft Office installation required
* Designed for server-side and automated environments

## Installation

Install the NuGet package:

```bash
dotnet add package XlsCrypt.NativeExcelEncryption
```

Or using the NuGet Package Manager:

```powershell
Install-Package XlsCrypt.NativeExcelEncryption
```

## Usage

### Encrypt

```csharp
using XlsxCrypt;

NativeExcelEncryption.EncryptFile(
    "input.xlsx",
    "encrypted.xlsx",
    "your-password");
```

### Decrypt

```csharp
using XlsxCrypt;

NativeExcelEncryption.DecryptFile(
    "encrypted.xlsx",
    "decrypted.xlsx",
    "your-password");
```

### Complete Example

```csharp
using XlsxCrypt;

string inputFile = @"C:\Excel\input.xlsx";
string encryptedFile = @"C:\Excel\encrypted.xlsx";
string decryptedFile = @"C:\Excel\decrypted.xlsx";

string password = "StrongPassword123!";

NativeExcelEncryption.EncryptFile(
    inputFile,
    encryptedFile,
    password);

NativeExcelEncryption.DecryptFile(
    encryptedFile,
    decryptedFile,
    password);
```

## How It Works

XlsCrypt uses Microsoft's Office Agile Encryption format to protect `.xlsx` workbooks.

The workbook package is encrypted using AES-256-CBC with 4096-byte segments. The encrypted package, encryption metadata, and Office DataSpaces information are stored in an OLE Compound File.

The encryption process includes:

* Password-based key derivation
* SHA-512 hashing
* AES-256-CBC encryption
* Random salts
* Password verification
* Encrypted workbook key
* HMAC-SHA512 integrity verification
* Office DataSpaces metadata
* `EncryptionInfo`
* `EncryptedPackage`

Decryption reverses this process and verifies the password and encrypted package integrity before producing the original `.xlsx` workbook.

## Why XlsCrypt?

XlsCrypt provides a native .NET approach to Excel workbook encryption without requiring:

* EPPlus
* ClosedXML
* Microsoft Office
* Excel COM automation

This makes it suitable for applications that need to protect Excel workbooks programmatically, particularly server-side and automated workloads.

## Compatibility

The library uses the Microsoft Office Agile Encryption format and is intended to produce password-protected `.xlsx` workbooks compatible with Microsoft Excel.

Always test encrypted workbooks with the Excel versions and environments relevant to your application before using the library in production.

## Security

This library implements cryptographic operations required by the Office Agile Encryption format.

The security of an encrypted workbook also depends on the password used to protect it.

Recommendations:

* Use strong, unique passwords.
* Do not hard-code passwords in source code.
* Do not log passwords.
* Store passwords securely.
* Test the library thoroughly before using it for highly sensitive or regulated data.

This project has not been presented as a replacement for a formal security review or cryptographic audit.

## Requirements

* .NET 10
* Windows

## License

MIT License.

See the [LICENSE](LICENSE) file for the complete license text.

## Repository

Source code and development history are available on GitHub:

https://github.com/pragmasujit/xlsxcrypt

## Disclaimer

XlsCrypt.NativeExcelEncryption is an independent open-source project and is not affiliated with, sponsored by, or endorsed by Microsoft Corporation.

Excel and Microsoft Office are trademarks of Microsoft Corporation.
