# Project 2: Secure File Sharing System

This repository contains the implementation of a secure, distributed file sharing system for CS161. The system provides end-to-end encryption, secure file sharing with access control, and efficient large file handling.

## Overview

The system implements a client-server architecture where:
- Files are encrypted and stored in chunks for efficient large file handling
- Users can share files with others through secure invitations
- Access can be revoked at any time, affecting all downstream users
- Bandwidth usage scales efficiently with file size and number of operations

## Key Features

- **Secure File Storage**: All data is encrypted using symmetric encryption with HMAC integrity verification
- **Efficient Append Operations**: O(1) bandwidth scaling for file appends regardless of file size
- **Multi-User Collaboration**: Support for complex sharing trees with granular access control
- **Access Revocation**: Owners can revoke access, affecting all downstream users
- **Large File Support**: Optimized for files with thousands of appends and millions of bytes

## Architecture

The system uses a 4-layer architecture:
1. **User Layer**: Handles authentication and user management
2. **Invitation Pointer Layer**: Maps filenames to invitation structures
3. **Invitation Layer**: Manages access control and sharing permissions
4. **File Layer**: Stores actual file content in encrypted chunks

## Testing

For comprehensive documentation, see the Project 2 Spec (https://cs161.org/proj2/).

Write your implementation in `client/client.go` and your integration tests in `client_test/client_test.go`. Optionally, you can also use `client/client_unittest.go` to write unit tests (e.g: to test your helper functions).

To test your implementation, run `go test -v` inside of the `client_test` directory. This will run all tests in both `client/client_unittest.go` and `client_test/client_test.go`.
