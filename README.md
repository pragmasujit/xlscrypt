# XlsCrypt.NativeExcelEncryption

Native .NET library for password-based encryption of Excel `.xlsx` workbooks.

## Features

* Native .NET implementation
* Excel-compatible workbook encryption
* Supports password-protected `.xlsx` files
* Uses the Office Agile Encryption format
* No EPPlus dependency
* No ClosedXML dependency
* No Microsoft Office installation required
* Designed for server-side and automated environments

## Installation

Install the NuGet package:

```bash
dotnet add package XlsCrypt.NativeExcelEncryption
```

Or from the NuGet Package Manager:

```powershell
Install-Package XlsCrypt.NativeExcelEncryption
```

## Usage

```csharp
using XlsCrypt.NativeExcelEncryption;

// Example:
//
// XlsCrypt.NativeExcelEncryption.Encrypt(
//     "input.xlsx",
//     "encrypted.xlsx",
//     "your-password");
```

> API details may vary depending on the version of the library.

## Why XlsCrypt?

XlsCrypt provides a native .NET approach to Excel workbook encryption without requiring third-party Excel manipulation libraries or an installed Microsoft Office application.

The goal is to provide a lightweight solution for applications that need to generate or protect Excel workbooks programmatically.

## Compatibility

The encrypted workbook uses Microsoft's Office Agile Encryption format and is intended to be compatible with Microsoft Excel.

Always test encrypted files with the Excel versions and environments relevant to your application.

## Security

This library implements cryptographic operations used by the Office encryption format.

Security-sensitive software should be reviewed and tested appropriately before being used for highly sensitive or regulated data.

Do not use weak passwords.

## Requirements

* .NET 10
* Windows

## License

MIT License.

See the [LICENSE](LICENSE)