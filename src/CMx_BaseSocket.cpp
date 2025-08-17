#include "CMx_BaseSocket.h"

// Default constructor
CMx_BaseSocket::CMx_BaseSocket()
{
    reset();
};

// Param constructor
CMx_BaseSocket::CMx_BaseSocket(bool isSSL, bool isServer)
{
    m_bIsConnected = false;
    m_bIsSSL = isSSL;
    m_bIsServer = isServer;
    m_bIsBlocking = true;
}

// Virtual destructor
CMx_BaseSocket::~CMx_BaseSocket()
{
    reset();
}

// Reset function
void CMx_BaseSocket::reset() {
    m_bIsConnected = false;
    m_bIsSSL = false;
    m_bIsServer = false;
    m_bIsBlocking = true;
}
