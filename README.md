# POCO HTTPS Client Project

A cross-platform HTTPS client application built using POCO C++ libraries and OpenSSL.

## Directory Structure
```
POCO-Buidl_Project/
├── CMakeLists.txt          # Build configuration
├── src/
│   ├── main.cpp           # Main application code
│   └── SSLHandler.cpp     # SSL handling implementation
└── thirdParty/
    ├── window/
    │   ├── Poco-1.14.2/
    │   └── openssl-3.5.2/
    ├── mac/
    │   ├── Poco-1.14.2/
    │   └── openssl-3.5.2/
    └── linux/
        ├── Poco-1.14.2/
        └── openssl-3.5.2/
```

## Prerequisites
- CMake 3.15 or higher
- C++17 compatible compiler
- Visual Studio 2022 (for Windows)
- Xcode (for macOS)
- GCC/Clang (for Linux)

## Dependencies
- POCO Libraries 1.14.2
  - Foundation
  - Net
  - NetSSL
  - Crypto
  - Util
- OpenSSL 3.5.2

## Building the Project

### Windows (Visual Studio 2022)
```powershell
# Create and configure build
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DTARGET_OS=windows

# Build the project
cmake --build build --config Release

# Run the application
.\build\Release\my_ssl_app.exe
```

### macOS
```bash
# Create and configure build
cmake -S . -B build -DTARGET_OS=mac

# Build the project
cmake --build build --config Release

# Run the application
./build/my_ssl_app
```

### Linux
```bash
# Create and configure build
cmake -S . -B build -DTARGET_OS=linux

# Build the project
cmake --build build --config Release

# Run the application
./build/my_ssl_app
```

## Build Options
- `-DTARGET_OS=windows` - Build for Windows
- `-DTARGET_OS=mac` - Build for macOS
- `-DTARGET_OS=linux` - Build for Linux

## Troubleshooting

### Common Issues

1. **Missing Dependencies**
   ```
   Error: Could not find POCO/OpenSSL
   ```
   - Verify thirdParty directory contains correct libraries for your platform
   - Check if paths in CMakeLists.txt match your directory structure

2. **Build Errors**
   ```
   Error: compiler not found
   ```
   - Ensure proper development tools are installed
   - Windows: Install Visual Studio 2022
   - macOS: Install Xcode
   - Linux: Install build-essential package

3. **Runtime Errors**
   ```
   Error: Cannot load shared library
   ```
   - Verify all DLLs/shared libraries are copied to executable directory
   - Check if PATH includes required runtime directories

## Development

### Adding New Features
1. Add source files to `src/` directory
2. Update `SRC_FILES` in CMakeLists.txt
3. Rebuild using appropriate platform command

### Testing
1. Build in Debug configuration for testing
2. Use included test endpoints in main.cpp
3. Verify SSL/TLS connections work properly

## License
[Add your license information here]