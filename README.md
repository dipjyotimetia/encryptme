# EncryptMe - File Encryption and Decryption in Go

## Problem Statement
Organizations need a reliable tool to protect their sensitive test data. EncryptMe is a simple solution aims to provide a trustworthy mechanism for securing files(text/yaml/json/etc...), ensuring that even if the files fall into the wrong hands, they remain unreadable without the correct decryption key, this also ensures a global standard for data security.


EncryptMe is a Go package that provides functions for encrypting and decrypting files using the AES-GCM encryption algorithm. This package allows you to secure the content of your files with a secret key, ensuring that only authorized parties can access the data.


![Alt text](docs\encryptmet.png)

## Features

- Encrypt any file using AES-GCM encryption.
- Decrypt encrypted files with the correct secret key.
- Easy-to-use functions for file encryption and decryption.

## Installation

You can install EncryptMe using Go modules:

```shell
go get github.com/dipjyotimetia/encryptme
```

## Usage

### Encrypt a File

To encrypt a file, use the `EncryptFile` function provided by the EncryptMe package. This function takes the following parameters:

- `contentFile`: The path to the file you want to encrypt.
- `secretKey`: The path to the secret key file used for encryption.
- `exportBin`: The path where the encrypted file will be saved.

Example:

```go
import "github.com/dipjyotimetia/encryptme"

func main() {
    encryptme.EncryptFile("plaintext.txt", "secret.key", "encrypted.bin")
}
```

### Decrypt a File

To decrypt a previously encrypted file, use the `DecryptFile` function. This function takes the following parameters:

- `importBin`: The path to the encrypted file.
- `secretKey`: The path to the secret key file used for decryption.
- `content`: The path where the decrypted content will be saved.

Example:

```go
import "github.com/dipjyotimetia/encryptme"

func main() {
    encryptme.DecryptFile("encrypted.bin", "secret.key", "decrypted.txt")
}
```

## Security Considerations

- Keep your secret key secure. Do not share it with unauthorized users.
- Ensure that you have proper access control for your secret key file.
- Use strong and unique secret keys for each encryption operation.

## Contributing

Contributions to EncryptMe are welcome! Feel free to open issues or pull requests if you have any improvements, bug fixes, or feature suggestions.
