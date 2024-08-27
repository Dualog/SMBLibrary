/* Copyright (C) 2017-2022 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client
{
    public interface ISMBClient
    {
        Task<(bool Success, string ErrorMessage)> ConnectAsync(string serverName, SMBTransportType transport, CancellationToken cancellationToken);

        Task<(bool Success, string ErrorMessage)> ConnectAsync(IPAddress serverAddress, SMBTransportType transport, CancellationToken cancellationToken);

        void Disconnect();

        Task<NTStatus> LoginAsync(string domainName, string userName, string password, CancellationToken cancellationToken);

        Task<NTStatus> LoginAsync(string domainName, string userName, string password, AuthenticationMethod authenticationMethod, CancellationToken cancellationToken);

        Task<NTStatus> LogoffAsync(CancellationToken cancellationToken);

        Task<(NTStatus status, IEnumerable<string> shares)> ListShares(CancellationToken cancellationToken);

        Task<(NTStatus status, ISMBFileStore share)> TreeConnectAsync(string shareName, CancellationToken cancellationToken);


        uint MaxReadSize
        {
            get;
        }

        uint MaxWriteSize
        {
            get;
        }

        bool IsConnected
        {
            get;
        }
    }
}
