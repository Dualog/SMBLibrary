/* Copyright (C) 2017-2024 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using SMBLibrary.Client.Authentication;
using SMBLibrary.NetBios;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Client
{
    public class SMB2Client : ISMBClient
    {
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        public static readonly uint ClientMaxTransactSize = 1048576;
        public static readonly uint ClientMaxReadSize = 1048576;
        public static readonly uint ClientMaxWriteSize = 1048576;
        private static readonly ushort DesiredCredits = 16;
        public static readonly int DefaultResponseTimeoutInMilliseconds = 15000;

        private string m_serverName;
        private SMBTransportType m_transport;
        private bool m_isConnected;
        private bool m_isLoggedIn;
        private Socket m_clientSocket;
        private ConnectionState m_connectionState;
        private int m_responseTimeoutInMilliseconds;

        private object m_incomingQueueLock = new object();
        private List<SMB2Command> m_incomingQueue = new List<SMB2Command>();
        private EventWaitHandle m_incomingQueueEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private SessionPacket m_sessionResponsePacket;
        private EventWaitHandle m_sessionResponseEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private uint m_messageID = 0;
        private SMB2Dialect m_dialect;
        private bool m_signingRequired;
        private byte[] m_signingKey;
        private bool m_encryptSessionData;
        private byte[] m_encryptionKey;
        private byte[] m_decryptionKey;
        private uint m_maxTransactSize;
        private uint m_maxReadSize;
        private uint m_maxWriteSize;
        private ulong m_sessionID;
        private byte[] m_securityBlob;
        private byte[] m_sessionKey;
        private byte[] m_preauthIntegrityHashValue; // SMB 3.1.1
        private ushort m_availableCredits = 1;

        public SMB2Client()
        {
        }

        /// <param name="serverName">
        /// When a Windows Server host is using Failover Cluster and Cluster Shared Volumes, each of those CSV file shares is associated
        /// with a specific host name associated with the cluster and is not accessible using the node IP address or node host name.
        /// </param>
        public Task<(bool Success, string ErrorMessage)> ConnectAsync(string serverName, SMBTransportType transport, CancellationToken cancellationToken)
        {
            return ConnectAsync(serverName, transport, DefaultResponseTimeoutInMilliseconds, cancellationToken);
        }

        public Task<(bool Success, string ErrorMessage)> ConnectAsync(IPAddress serverAddress, SMBTransportType transport, CancellationToken cancellationToken)
        {
            return ConnectAsync(serverAddress, transport, DefaultResponseTimeoutInMilliseconds, cancellationToken);
        }

        // /// <param name="serverName">
        // /// When a Windows Server host is using Failover Cluster and Cluster Shared Volumes, each of those CSV file shares is associated
        // /// with a specific host name associated with the cluster and is not accessible using the node IP address or node host name.
        // /// </param>
        public Task<(bool Success, string ErrorMessage)> ConnectAsync(string serverName, SMBTransportType transport, int responseTimeoutInMilliseconds, CancellationToken cancellationToken)
        {
            m_serverName = serverName;
            IPAddress[] hostAddresses = Dns.GetHostAddresses(serverName);
            if (hostAddresses.Length == 0)
            {
                throw new Exception(String.Format("Cannot resolve host name {0} to an IP address", serverName));
            }
            IPAddress serverAddress = IPAddressHelper.SelectAddressPreferIPv4(hostAddresses);
            return ConnectAsync(serverAddress, transport, responseTimeoutInMilliseconds, cancellationToken);
        }

        public Task<(bool Success, string ErrorMessage)> ConnectAsync(IPAddress serverAddress, SMBTransportType transport, int responseTimeoutInMilliseconds, CancellationToken cancellationToken)
        {
            int port = (transport == SMBTransportType.DirectTCPTransport ? DirectTCPPort : NetBiosOverTCPPort);
            return ConnectAsync(serverAddress, transport, port, responseTimeoutInMilliseconds, cancellationToken);
        }
        
        public async Task<(bool Success, string ErrorMessage)> ConnectAsync(IPAddress serverAddress, SMBTransportType transport, int port, int responseTimeoutInMilliseconds, CancellationToken cancellationToken)
        {
            if (m_serverName == null)
            {
                m_serverName = serverAddress.ToString();
            }

            m_transport = transport;
            if (!m_isConnected)
            {
                m_responseTimeoutInMilliseconds = responseTimeoutInMilliseconds;

                var ConResult1 = ConnectSocket(serverAddress, port);
                if (!ConResult1.Success)
                {
                    return ConResult1;
                }

                if (transport == SMBTransportType.NetBiosOverTCP)
                {
                    SessionRequestPacket sessionRequest = new SessionRequestPacket();
                    sessionRequest.CalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServerService);
                    sessionRequest.CallingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService);
                    await TrySendPacketAsync(m_clientSocket, sessionRequest, cancellationToken);

                    SessionPacket sessionResponsePacket = WaitForSessionResponsePacket();
                    if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                    {
                        m_clientSocket.Disconnect(false);
                        var ConResult2 = ConnectSocket(serverAddress, port);
                        if (!ConResult2.Success)
                        {
                            return ConResult2;
                        }

                        NameServiceClient nameServiceClient = new NameServiceClient(serverAddress);
                        string serverName = nameServiceClient.GetServerName();
                        if (serverName == null)
                        {
                            return (false, "Could not get server name.");
                        }

                        sessionRequest.CalledName = serverName;
                        await TrySendPacketAsync(m_clientSocket, sessionRequest, cancellationToken);

                        sessionResponsePacket = WaitForSessionResponsePacket();
                        if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                        {
                            return (false, "Timeout while waiting for session response packet");
                        }
                    }
                }

                var supportsDialect = await NegotiateDialectAsync(cancellationToken);
                if (!supportsDialect.Success)
                {
                    m_clientSocket.Close();
                    return (false, supportsDialect.ErrorMessage);
                }
                else
                {
                    m_isConnected = true;
                }
            }
            return (m_isConnected, String.Empty);
        }

        private (bool Success, string ErrorMessage) ConnectSocket(IPAddress serverAddress, int port)
        {
            m_clientSocket = new Socket(serverAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                m_clientSocket.Connect(serverAddress, port);
            }
            catch (SocketException e)
            {
                return (false, "Could not establish connection to a remote host: " + e.Message);
            }

            m_connectionState = new ConnectionState(m_clientSocket);
            NBTConnectionReceiveBuffer buffer = m_connectionState.ReceiveBuffer;
            m_clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), m_connectionState);
            return (true, string.Empty);
        }

        private async Task<(bool Success, string ErrorMessage)> NegotiateDialectAsync(CancellationToken cancellationToken)
        {
            NegotiateRequest request = new NegotiateRequest();
            request.SecurityMode = SecurityMode.SigningEnabled;
            request.Capabilities = Capabilities.Encryption;
            request.ClientGuid = Guid.NewGuid();
            request.ClientStartTime = DateTime.Now;
            request.Dialects.Add(SMB2Dialect.SMB202);
            request.Dialects.Add(SMB2Dialect.SMB210);
            request.Dialects.Add(SMB2Dialect.SMB300);
            await TrySendCommandAsync(request, cancellationToken);
            var command = WaitForCommand(request.MessageID);

            if (command == null)
                return (false, "Negotiate failed. Server did not respond. Either not a SMB server or is not supporting SMBv2 or 3.");

            if (command.Header.Status == NTStatus.STATUS_SUCCESS)
            {
                NegotiateResponse response = command as NegotiateResponse;
                m_dialect = response.DialectRevision;
                m_signingRequired = (response.SecurityMode & SecurityMode.SigningRequired) > 0;
                m_maxTransactSize = Math.Min(response.MaxTransactSize, ClientMaxTransactSize);
                m_maxReadSize = Math.Min(response.MaxReadSize, ClientMaxReadSize);
                m_maxWriteSize = Math.Min(response.MaxWriteSize, ClientMaxWriteSize);
                m_securityBlob = response.SecurityBuffer;
                return (true, String.Empty);
            }

            return command.Header.Status switch
            {
                NTStatus.STATUS_INVALID_PARAMETER => (false, "Negotiate failed with invalid parameter."),
                NTStatus.STATUS_NOT_SUPPORTED => (false, "Negotiate failed. Server not supporting SMB version 2.0.2, 2.1 or 3.0."),
                _ => (false, "Negotiate failed: " + command.Header.Status),
            };
        }

        public void Disconnect()
        {
            if (m_isConnected)
            {
                m_clientSocket.Disconnect(false);
                m_clientSocket.Close();
                lock (m_connectionState.ReceiveBuffer)
                {
                    m_connectionState.ReceiveBuffer.Dispose();
                }
                m_isConnected = false;
                m_messageID = 0;
                m_sessionID = 0;
                m_availableCredits = 1;
            }
        }

        public Task<NTStatus> LoginAsync(string domainName, string userName, string password, CancellationToken cancellationToken)
        {
            return LoginAsync(domainName, userName, password, AuthenticationMethod.NTLMv2, cancellationToken);
        }

        public Task<NTStatus> LoginAsync(string domainName, string userName, string password, AuthenticationMethod authenticationMethod, CancellationToken cancellationToken)
        {
            var spn = $"cifs/{m_serverName}";
            var authenticationClient = new NTLMAuthenticationClient(domainName, userName, password, spn, authenticationMethod);
            return Login(authenticationClient, cancellationToken);
        }

        public async Task<NTStatus> Login(IAuthenticationClient authenticationClient, CancellationToken cancellationToken)
        {
            if (!m_isConnected)
            {
                throw new InvalidOperationException("A connection must be successfully established before attempting login");
            }

            byte[] negotiateMessage = authenticationClient.InitializeSecurityContext(m_securityBlob);
            if (negotiateMessage == null)
            {
                return NTStatus.SEC_E_INVALID_TOKEN;
            }

            SessionSetupRequest request = new SessionSetupRequest();
            request.SecurityMode = SecurityMode.SigningEnabled;
            request.SecurityBuffer = negotiateMessage;
            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED && response is SessionSetupResponse)
                {
                    byte[] authenticateMessage = authenticationClient.InitializeSecurityContext(((SessionSetupResponse)response).SecurityBuffer);
                    if (authenticateMessage == null)
                    {
                        return NTStatus.SEC_E_INVALID_TOKEN;
                    }
                    m_sessionKey = authenticationClient.GetSessionKey();

                    m_sessionID = response.Header.SessionID;
                    request = new SessionSetupRequest();
                    request.SecurityMode = SecurityMode.SigningEnabled;
                    request.SecurityBuffer = authenticateMessage;
                    await TrySendCommandAsync(request, cancellationToken);
                    response = WaitForCommand(request.MessageID);
                    if (response != null)
                    {
                        m_isLoggedIn = (response.Header.Status == NTStatus.STATUS_SUCCESS);
                        if (m_isLoggedIn)
                        {
                            SessionFlags sessionFlags = ((SessionSetupResponse)response).SessionFlags;
                            if ((sessionFlags & SessionFlags.IsGuest) > 0)
                            {
                                // [MS-SMB2] 3.2.5.3.1 If the SMB2_SESSION_FLAG_IS_GUEST bit is set in the SessionFlags field of the SMB2
                                // SESSION_SETUP Response and if RequireMessageSigning is FALSE, Session.SigningRequired MUST be set to FALSE.
                                m_signingRequired = false;
                            }
                            else
                            {
                                m_signingKey = SMB2Cryptography.GenerateSigningKey(m_sessionKey, m_dialect, m_preauthIntegrityHashValue);
                            }

                            if (m_dialect >= SMB2Dialect.SMB300)
                            {
                                m_encryptSessionData = (sessionFlags & SessionFlags.EncryptData) > 0;
                                m_encryptionKey = SMB2Cryptography.GenerateClientEncryptionKey(m_sessionKey, m_dialect, m_preauthIntegrityHashValue);
                                m_decryptionKey = SMB2Cryptography.GenerateClientDecryptionKey(m_sessionKey, m_dialect, m_preauthIntegrityHashValue);
                            }
                        }
                        return response.Header.Status;
                    }
                }
                else
                {
                    return response.Header.Status;
                }
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTStatus> LogoffAsync(CancellationToken cancellationToken)
        {
            if (!m_isConnected)
            {
                throw new InvalidOperationException("A login session must be successfully established before attempting logoff");
            }

            LogoffRequest request = new LogoffRequest();
            await TrySendCommandAsync(request, cancellationToken);

            SMB2Command response = WaitForCommand(request.MessageID);
            if (response != null)
            {
                m_isLoggedIn = (response.Header.Status != NTStatus.STATUS_SUCCESS);
                return response.Header.Status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<(NTStatus status, IEnumerable<string> shares)> ListShares(CancellationToken cancellationToken)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before retrieving share list");
            }

            var (status, namedPipeShare) = await TreeConnectAsync("IPC$", cancellationToken);
            if (namedPipeShare == null)
            {
                return (status, Enumerable.Empty<string>());
            }

            IEnumerable<string> shares = null;
            (status, shares) = await ServerServiceHelper.ListShares(namedPipeShare, m_serverName, SMBLibrary.Services.ShareType.DiskDrive, cancellationToken);
            await namedPipeShare.DisconnectAsync();
            return (status, shares);
        }

        public async Task<(NTStatus status, ISMBFileStore share)> TreeConnectAsync(string shareName, CancellationToken cancellationToken)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before connecting to a share");
            }

            string sharePath = string.Format(@"\\{0}\{1}", m_serverName, shareName);
            TreeConnectRequest request = new TreeConnectRequest();
            request.Path = sharePath;
            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = WaitForCommand(request.MessageID);


            NTStatus status = NTStatus.STATUS_INVALID_SMB;
            if (response != null)
            {
                status = response.Header.Status;
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is TreeConnectResponse)
                {
                    bool encryptShareData = (((TreeConnectResponse)response).ShareFlags & ShareFlags.EncryptData) > 0;
                    var share = new SMB2FileStore(this, response.Header.TreeID, m_encryptSessionData || encryptShareData);
                    return (status, share);
                }
            }
            return (status, null);
        }

        private void OnClientSocketReceive(IAsyncResult ar)
        {
            ConnectionState state = (ConnectionState)ar.AsyncState;
            Socket clientSocket = state.ClientSocket;

            lock (state.ReceiveBuffer)
            {
                int numberOfBytesReceived = 0;
                try
                {
                    numberOfBytesReceived = clientSocket.EndReceive(ar);
                }
                catch (ArgumentException) // The IAsyncResult object was not returned from the corresponding synchronous method on this class.
                {
                    m_isConnected = false;
                    state.ReceiveBuffer.Dispose();
                    return;
                }
                catch (ObjectDisposedException)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] EndReceive ObjectDisposedException");
                    state.ReceiveBuffer.Dispose();
                    return;
                }
                catch (SocketException ex)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] EndReceive SocketException: " + ex.Message);
                    state.ReceiveBuffer.Dispose();
                    return;
                }

                if (numberOfBytesReceived == 0)
                {
                    m_isConnected = false;
                    state.ReceiveBuffer.Dispose();
                }
                else
                {
                    NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
                    buffer.SetNumberOfBytesReceived(numberOfBytesReceived);
                    ProcessConnectionBuffer(state);

                    if (clientSocket.Connected)
                    {
                        try
                        {
                            clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), state);
                        }
                        catch (ObjectDisposedException)
                        {
                            m_isConnected = false;
                            Log("[ReceiveCallback] BeginReceive ObjectDisposedException");
                            buffer.Dispose();
                        }
                        catch (SocketException ex)
                        {
                            m_isConnected = false;
                            Log("[ReceiveCallback] BeginReceive SocketException: " + ex.Message);
                            buffer.Dispose();
                        }
                    }
                }
            }
        }

        private void ProcessConnectionBuffer(ConnectionState state)
        {
            NBTConnectionReceiveBuffer receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacket packet = null;
                try
                {
                    packet = receiveBuffer.DequeuePacket();
                }
                catch (Exception)
                {
                    Log("[ProcessConnectionBuffer] Invalid packet");
                    state.ClientSocket.Close();
                    state.ReceiveBuffer.Dispose();
                    break;
                }

                if (packet != null)
                {
                    ProcessPacket(packet, state);
                }
            }
        }

        private void ProcessPacket(SessionPacket packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                byte[] messageBytes;
                if (m_dialect >= SMB2Dialect.SMB300 && SMB2TransformHeader.IsTransformHeader(packet.Trailer, 0))
                {
                    SMB2TransformHeader transformHeader = new SMB2TransformHeader(packet.Trailer, 0);
                    byte[] encryptedMessage = ByteReader.ReadBytes(packet.Trailer, SMB2TransformHeader.Length, (int)transformHeader.OriginalMessageSize);
                    messageBytes = SMB2Cryptography.DecryptMessage(m_decryptionKey, transformHeader, encryptedMessage);
                }
                else
                {
                    messageBytes = packet.Trailer;
                }

                SMB2Command command;
                try
                {
                    command = SMB2Command.ReadResponse(messageBytes, 0);
                }
                catch (Exception ex)
                {
                    Log("Invalid SMB2 response: " + ex.Message);
                    state.ClientSocket.Close();
                    m_isConnected = false;
                    state.ReceiveBuffer.Dispose();
                    return;
                }

                if (m_preauthIntegrityHashValue != null && (command is NegotiateResponse || (command is SessionSetupResponse sessionSetupResponse && sessionSetupResponse.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED)))
                {
                    m_preauthIntegrityHashValue = SMB2Cryptography.ComputeHash(HashAlgorithm.SHA512, ByteUtils.Concatenate(m_preauthIntegrityHashValue, messageBytes));
                }

                m_availableCredits += command.Header.Credits;

                if (m_transport == SMBTransportType.DirectTCPTransport && command is NegotiateResponse)
                {
                    NegotiateResponse negotiateResponse = (NegotiateResponse)command;
                    if ((negotiateResponse.Capabilities & Capabilities.LargeMTU) > 0)
                    {
                        // [MS-SMB2] 3.2.5.1 Receiving Any Message - If the message size received exceeds Connection.MaxTransactSize, the client SHOULD disconnect the connection.
                        // Note: Windows clients do not enforce the MaxTransactSize value.
                        // We use a value that we have observed to work well with both Microsoft and non-Microsoft servers.
                        // see https://github.com/TalAloni/SMBLibrary/issues/239
                        int serverMaxTransactSize = (int)Math.Max(negotiateResponse.MaxTransactSize, negotiateResponse.MaxReadSize);
                        int maxPacketSize = SessionPacket.HeaderLength + (int)Math.Min(serverMaxTransactSize, ClientMaxTransactSize) + 256;
                        if (maxPacketSize > state.ReceiveBuffer.Buffer.Length)
                        {
                            state.ReceiveBuffer.IncreaseBufferSize(maxPacketSize);
                        }
                    }
                }

                // [MS-SMB2] 3.2.5.1.2 - If the MessageId is 0xFFFFFFFFFFFFFFFF, this is not a reply to a previous request,
                // and the client MUST NOT attempt to locate the request, but instead process it as follows:
                // If the command field in the SMB2 header is SMB2 OPLOCK_BREAK, it MUST be processed as specified in 3.2.5.19.
                // Otherwise, the response MUST be discarded as invalid.
                if (command.Header.MessageID != 0xFFFFFFFFFFFFFFFF || command.Header.Command == SMB2CommandName.OplockBreak)
                {
                    lock (m_incomingQueueLock)
                    {
                        m_incomingQueue.Add(command);
                        m_incomingQueueEventHandle.Set();
                    }
                }
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                m_sessionResponsePacket = packet;
                m_sessionResponseEventHandle.Set();
            }
            else if (packet is SessionKeepAlivePacket && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                // [RFC 1001] NetBIOS session keep alives do not require a response from the NetBIOS peer
            }
            else
            {
                Log("Inappropriate NetBIOS session packet");
                state.ClientSocket.Close();
                state.ReceiveBuffer.Dispose();
            }
        }

        internal SMB2Command WaitForCommand(ulong messageID)
        {
            return WaitForCommand(messageID, out bool _);
        }

        internal SMB2Command WaitForCommand(ulong messageID, out bool connectionTerminated)
        {
            connectionTerminated = false;
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < m_responseTimeoutInMilliseconds && !(connectionTerminated = !m_clientSocket.Connected))
            {
                lock (m_incomingQueueLock)
                {
                    for (int index = 0; index < m_incomingQueue.Count; index++)
                    {
                        SMB2Command command = m_incomingQueue[index];

                        if (command.Header.MessageID == messageID)
                        {
                            m_incomingQueue.RemoveAt(index);
                            if (command.Header.IsAsync && command.Header.Status == NTStatus.STATUS_PENDING)
                            {
                                index--;
                                continue;
                            }
                            return command;
                        }
                    }
                }
                m_incomingQueueEventHandle.WaitOne(100);
            }
            return null;
        }

        internal SessionPacket WaitForSessionResponsePacket()
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            while (stopwatch.ElapsedMilliseconds < m_responseTimeoutInMilliseconds)
            {
                if (m_sessionResponsePacket != null)
                {
                    SessionPacket result = m_sessionResponsePacket;
                    m_sessionResponsePacket = null;
                    return result;
                }

                m_sessionResponseEventHandle.WaitOne(100);
            }

            return null;
        }

        private void Log(string message)
        {
            System.Diagnostics.Debug.Print(message);
        }

        internal Task TrySendCommandAsync(SMB2Command request, CancellationToken cancellationToken)
        {
            return TrySendCommandAsync(request, m_encryptSessionData, cancellationToken);
        }

        private async Task<bool> WaitForAmountOfCredits(ushort amountOfCreditsNeeded, int timeout, CancellationToken cancellationToken)
        {
            int waitTimeMs = timeout;
            await Task.Run(async () =>
            {
                while (m_availableCredits < amountOfCreditsNeeded && waitTimeMs > 0)
                {
                    await Task.Delay(100);
                    waitTimeMs -= 100;
                }
            }, cancellationToken);
            return m_availableCredits >= amountOfCreditsNeeded;
        }

        internal async Task TrySendCommandAsync(SMB2Command request, bool encryptData, CancellationToken cancellationToken)
        {
            if (m_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTCP)
            {
                request.Header.CreditCharge = 0;
                request.Header.Credits = 1;
                m_availableCredits -= 1;
            }
            else
            {
                if (request.Header.CreditCharge == 0)
                {
                    request.Header.CreditCharge = 1;
                }

                if (m_availableCredits < request.Header.CreditCharge)
                {
                    // SMB server did not send packet with credits on time (i.e. throttling, or too much connections) or the credit packet was lost.
                    if (!await WaitForAmountOfCredits(request.Header.CreditCharge, m_responseTimeoutInMilliseconds, cancellationToken))
                    {
                        throw new Exception($"Not enough credits ({m_availableCredits} Available, {request.Header.CreditCharge} CreditCharge).");
                    }
                }

                m_availableCredits -= request.Header.CreditCharge;

                if (m_availableCredits < DesiredCredits)
                {
                    request.Header.Credits += (ushort)(DesiredCredits - m_availableCredits);
                }
            }

            request.Header.MessageID = m_messageID;
            request.Header.SessionID = m_sessionID;
            // [MS-SMB2] If the client encrypts the message [..] then the client MUST set the Signature field of the SMB2 header to zero
            if (m_signingRequired && !encryptData)
            {
                request.Header.IsSigned = (m_sessionID != 0 && ((request.CommandName == SMB2CommandName.TreeConnect || request.Header.TreeID != 0) ||
                                                                (m_dialect >= SMB2Dialect.SMB300 && request.CommandName == SMB2CommandName.Logoff)));
                if (request.Header.IsSigned)
                {
                    request.Header.Signature = new byte[16]; // Request could be reused
                    byte[] buffer = request.GetBytes();
                    byte[] signature = SMB2Cryptography.CalculateSignature(m_signingKey, m_dialect, buffer, 0, buffer.Length);
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    request.Header.Signature = ByteReader.ReadBytes(signature, 0, 16);
                }
            }

            await TrySendCommandAsync(m_clientSocket, request, encryptData ? m_encryptionKey : null, cancellationToken);
            if (m_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTCP)
            {
                m_messageID++;
            }
            else
            {
                m_messageID += request.Header.CreditCharge;
            }
        }

        /// <remarks>SMB 3.1.1 only</remarks>
        private List<NegotiateContext> GetNegotiateContextList()
        {
            PreAuthIntegrityCapabilities preAuthIntegrityCapabilities = new PreAuthIntegrityCapabilities();
            preAuthIntegrityCapabilities.HashAlgorithms.Add(HashAlgorithm.SHA512);
            preAuthIntegrityCapabilities.Salt = new byte[32];
            new Random().NextBytes(preAuthIntegrityCapabilities.Salt);

            EncryptionCapabilities encryptionCapabilities = new EncryptionCapabilities();
            encryptionCapabilities.Ciphers.Add(CipherAlgorithm.Aes128Ccm);

            return new List<NegotiateContext>()
            {
                preAuthIntegrityCapabilities,
                encryptionCapabilities
            };
        }

        public uint MaxTransactSize
        {
            get
            {
                return m_maxTransactSize;
            }
        }

        public uint MaxReadSize
        {
            get
            {
                return m_maxReadSize;
            }
        }

        public uint MaxWriteSize
        {
            get
            {
                return m_maxWriteSize;
            }
        }
        
        public bool IsConnected
        {
            get
            {
                return m_isConnected;
            }
        }

        public Task TrySendCommandAsync(Socket socket, SMB2Command request, byte[] encryptionKey, CancellationToken cancellationToken = default)
        {
            SessionMessagePacket packet = new SessionMessagePacket();
            if (encryptionKey != null)
            {
                byte[] requestBytes = request.GetBytes();
                packet.Trailer = SMB2Cryptography.TransformMessage(encryptionKey, requestBytes, request.Header.SessionID);
            }
            else
            {
                packet.Trailer = request.GetBytes();
                if (m_preauthIntegrityHashValue != null && (request is NegotiateRequest || request is SessionSetupRequest))
                {
                    m_preauthIntegrityHashValue = SMB2Cryptography.ComputeHash(HashAlgorithm.SHA512, ByteUtils.Concatenate(m_preauthIntegrityHashValue, packet.Trailer));
                }
            }

            return TrySendPacketAsync(socket, packet, cancellationToken);
        }

        public async Task TrySendPacketAsync(Socket socket, SessionPacket packet, CancellationToken cancellationToken = default)
        {
            try
            {
                var packetBytes = packet.GetBytes().AsMemory();
                await socket.SendAsync(packetBytes, SocketFlags.None, cancellationToken);
            }
            catch (SocketException)
            {
                m_isConnected = false;
            }
            catch (ObjectDisposedException)
            {
                m_isConnected = false;
            }
        }
    }
}
