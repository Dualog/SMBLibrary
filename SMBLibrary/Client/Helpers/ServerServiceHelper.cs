/* Copyright (C) 2014-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SMBLibrary.RPC;
using SMBLibrary.Services;
using Utilities;

namespace SMBLibrary.Client
{
    public class ServerServiceHelper
    {
        public static Task<(NTStatus status, IEnumerable<string> result)> ListShares(INTFileStore namedPipeShare, ShareType? shareType, CancellationToken cancellationToken)
        {
            return ListShares(namedPipeShare, "*", shareType, cancellationToken);
        }

        /// <param name="serverName">
        /// When a Windows Server host is using Failover Cluster & Cluster Shared Volumes, each of those CSV file shares is associated
        /// with a specific host name associated with the cluster and is not accessible using the node IP address or node host name.
        /// </param>
        public static async Task<(NTStatus status, IEnumerable<string> result)> ListShares(INTFileStore namedPipeShare, string serverName, ShareType? shareType, CancellationToken cancellationToken)
        {
            var (status, pipeHandle, maxTransmitFragmentSize) = await NamedPipeHelper.BindPipe(namedPipeShare, ServerService.ServicePipeName, ServerService.ServiceInterfaceGuid, ServerService.ServiceVersion, cancellationToken);
            if (status != NTStatus.STATUS_SUCCESS)
                return (status, Enumerable.Empty<string>());

            NetrShareEnumRequest shareEnumRequest = new NetrShareEnumRequest();
            shareEnumRequest.InfoStruct = new ShareEnum();
            shareEnumRequest.InfoStruct.Level = 1;
            shareEnumRequest.InfoStruct.Info = new ShareInfo1Container();
            shareEnumRequest.PreferedMaximumLength = UInt32.MaxValue;
            shareEnumRequest.ServerName = serverName;
            RequestPDU requestPDU = new RequestPDU();
            requestPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            requestPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
            requestPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            requestPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
            requestPDU.OpNum = (ushort)ServerServiceOpName.NetrShareEnum;
            requestPDU.Data = shareEnumRequest.GetBytes();
            requestPDU.AllocationHint = (uint)requestPDU.Data.Length;

            var input = requestPDU.GetBytes();
            int maxOutputLength = maxTransmitFragmentSize;
            byte[] output;
            (status, output) = await namedPipeShare.DeviceIOControl(pipeHandle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, maxOutputLength, cancellationToken);

            if (status != NTStatus.STATUS_SUCCESS)
            {
                return (status, Enumerable.Empty<string>());
            }
            ResponsePDU responsePDU = RPCPDU.GetPDU(output, 0) as ResponsePDU;
            if (responsePDU == null)
            {
                status = NTStatus.STATUS_NOT_SUPPORTED;
                return (status, Enumerable.Empty<string>());
            }

            byte[] responseData = responsePDU.Data;
            while ((responsePDU.Flags & PacketFlags.LastFragment) == 0)
            {
                (status, output) = await namedPipeShare.ReadFileAsync(pipeHandle, 0, maxOutputLength, cancellationToken);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return (status, Enumerable.Empty<string>());
                }
                responsePDU = RPCPDU.GetPDU(output, 0) as ResponsePDU;
                if (responsePDU == null)
                {
                    status = NTStatus.STATUS_NOT_SUPPORTED;
                    return (status, Enumerable.Empty<string>());
                }
                responseData = ByteUtils.Concatenate(responseData, responsePDU.Data);
            }
            await namedPipeShare.CloseFileAsync(pipeHandle, cancellationToken);
            NetrShareEnumResponse shareEnumResponse = new NetrShareEnumResponse(responseData);
            ShareInfo1Container shareInfo1 = shareEnumResponse.InfoStruct.Info as ShareInfo1Container;
            if (shareInfo1 == null || shareInfo1.Entries == null)
            {
                if (shareEnumResponse.Result == Win32Error.ERROR_ACCESS_DENIED)
                {
                    status = NTStatus.STATUS_ACCESS_DENIED;
                }
                else
                {
                    status = NTStatus.STATUS_NOT_SUPPORTED;
                }

                return (status, Enumerable.Empty<string>());
            }

            List<string> result = new List<string>();
            foreach (ShareInfo1Entry entry in shareInfo1.Entries)
            {
                if (!shareType.HasValue || shareType.Value == entry.ShareType.ShareType)
                {
                    result.Add(entry.NetName.Value);
                }
            }
            return (status, result);
        }
    }
}
