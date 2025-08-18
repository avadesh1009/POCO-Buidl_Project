#include "Mx_BaseSocket.h"

/**
 * @class CMx_BaseSocket
 * @brief Base class for socket abstraction (SSL or non-SSL).
 *
 * This class provides a base implementation for common socket attributes,
 * connection state management, and reset functionality. 
 * It is designed to be inherited by more specific socket implementations 
 * (e.g., secure or plain sockets).
 */

// ============================================================================
// Constructors / Destructor
// ============================================================================

/**
 * @brief Default constructor.
 *
 * Initializes the socket object by calling reset() 
 * which sets all flags to their default values.
 */
CMx_BaseSocket::CMx_BaseSocket()
{
    reset();
}

/**
 * @brief Parameterized constructor.
 *
 * @param isSSL     Whether the socket is SSL-enabled.
 * @param isServer  Whether the socket is operating in server mode.
 *
 * Initializes the socket with explicit SSL and server mode flags.
 * Sets connection status to false and blocking mode to true.
 */
CMx_BaseSocket::CMx_BaseSocket(mx_bool isSSL, mx_bool isServer)
{
    m_bIsConnected = false;
    m_bIsSSL       = isSSL;
    m_bIsServer    = isServer;
    m_bIsBlocking  = true;
}

/**
 * @brief Virtual destructor.
 *
 * Calls reset() to ensure socket flags are restored 
 * to their safe default state.
 */
CMx_BaseSocket::~CMx_BaseSocket()
{
    reset();
}

// ============================================================================
// Reset
// ============================================================================

void CMx_BaseSocket::reset()
{
    m_bIsConnected = false;
    m_bIsSSL       = false;
    m_bIsServer    = false;
    m_bIsBlocking  = true;
}
