# Rust Authorization Server

A modern, secure authorization server implementation in Rust, following OAuth 2.0 specifications and best practices.

## Overview

This project implements a robust authorization server that manages authentication and authorization processes. It's built with a hexagonal architecture (ports and adapters pattern) to ensure modularity and maintainability.

## Features

- OAuth 2.0 compliant authorization server
- PKCE (Proof Key for Code Exchange) support
- Modular architecture using hexagonal design
- Async/await support with Tokio
- Type-safe error handling
- Secure token management
- Extensible adapter system

## Project Structure

```
src/
├── adapter/          # Implementation of ports
│   ├── inbound/      # Inbound adapters (HTTP, gRPC, etc.)
│   └── outbound/     # Outbound adapters (DB, external services)
├── core/             # Core domain logic
│   └── domain/       # Domain models and business logic
└── port/            # Interface definitions
    ├── inbound/     # Input ports (use cases)
    └── outbound/    # Output ports (repositories, external services)
```

## Technical Stack

- **Runtime**: Tokio for async operations
- **Authentication**: OAuth2 implementation with PKCE support
- **Error Handling**: Custom error types with thiserror
- **Testing**: Wiremock for HTTP mocking
- **Cryptography**: SHA-2 for secure hashing
- **Encoding**: Base64, URL encoding support

## Prerequisites

- Rust 1.76 or higher
- Cargo package manager

## Getting Started

1. Clone the repository:
```bash
git clone https://github.com/yourusername/rust-authzn.git
```

2. Build the project:
```bash
cargo build
```

3. Run tests:
```bash
cargo test
```

## Development

The project follows hexagonal architecture principles:

- **Ports**: Define interfaces for the application
- **Adapters**: Implement the interfaces
- **Core**: Contains business logic and domain models

### Adding New Features

1. Define the port interface in `src/port`
2. Implement the core logic in `src/core`
3. Create adapters in `src/adapter`
4. Add tests for new functionality

## Testing

The project includes:
- Unit tests for core logic
- Integration tests with mocked external services
- Comprehensive OAuth flow testing

## Security Considerations

- Implements PKCE for enhanced security
- Uses secure cryptographic functions
- Follows OAuth 2.0 security best practices

## Future Enhancements

- [ ] OpenID Connect support
- [ ] Additional OAuth 2.0 grant types
- [ ] Rate limiting
- [ ] Enhanced monitoring and logging
- [ ] Database integration
- [ ] Admin interface