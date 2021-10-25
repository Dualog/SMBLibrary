/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Client
{
    public class SMB2FileStore : ISMBFileStore
    {
        private const int BytesPerCredit = 65536;

        private SMB2Client m_client;
        private uint m_treeID;
        private bool m_encryptShareData;

        public SMB2FileStore(SMB2Client client, uint treeID, bool encryptShareData)
        {
            m_client = client;
            m_treeID = treeID;
            m_encryptShareData = encryptShareData;
        }

        public async Task<(NTStatus status, object handle, FileStatus fileStatus)> CreateFile(string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext, CancellationToken cancellationToken)
        {
            CreateRequest request = new CreateRequest();
            request.Name = path;
            request.DesiredAccess = desiredAccess;
            request.FileAttributes = fileAttributes;
            request.ShareAccess = shareAccess;
            request.CreateDisposition = createDisposition;
            request.CreateOptions = createOptions;
            request.ImpersonationLevel = ImpersonationLevel.Impersonation;
            await TrySendCommandAsync(request, cancellationToken);

            SMB2Command response = m_client.WaitForCommand(request.MessageID);

            var fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
            if (response != null)
            {
                object handle = null;

                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is CreateResponse)
                {
                    CreateResponse createResponse = ((CreateResponse)response);
                    handle = createResponse.FileId;
                    fileStatus = ToFileStatus(createResponse.CreateAction);
                }
                return (response.Header.Status, handle, fileStatus);
            }

            return (NTStatus.STATUS_INVALID_SMB, null, fileStatus);
        }

        public async Task<NTStatus> CloseFileAsync(object handle, CancellationToken cancellationToken)
        {
            CloseRequest request = new CloseRequest();
            request.FileId = (FileID)handle;
            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<(NTStatus status, byte[] data)> ReadFileAsync(object handle, long offset, int maxCount, CancellationToken cancellationToken)
        {
            ReadRequest request = new ReadRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxCount / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.ReadLength = (uint)maxCount;
            
            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                byte[] data = null;
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is ReadResponse)
                {
                    data = ((ReadResponse)response).Data;
                }
                return (response.Header.Status, data);
            }

            return (NTStatus.STATUS_INVALID_SMB, null);
        }

        public async Task<(NTStatus status, int numberOfBytesWritten)> WriteFileAsync(object handle, long offset, byte[] data, CancellationToken cancellationToken)
        {
            WriteRequest request = new WriteRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)data.Length / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.Data = data;

            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                int numberOfBytesWritten = 0;
                
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is WriteResponse)
                {
                    numberOfBytesWritten = (int)((WriteResponse)response).Count;
                }

                return (response.Header.Status, numberOfBytesWritten);
            }

            return (NTStatus.STATUS_INVALID_SMB, 0);
        }

        public async Task<NTStatus> FlushFileBuffersAsync(object handle, CancellationToken cancellationToken)
        {
            FlushRequest request = new FlushRequest();
            request.FileId = (FileID) handle;

            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is FlushResponse)
                {
                    return response.Header.Status;
                }
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock)
        {
            throw new NotImplementedException();
        }

        public NTStatus UnlockFile(object handle, long byteOffset, long length)
        {
            throw new NotImplementedException();
        }

        public async Task<(NTStatus status, IEnumerable<QueryDirectoryFileInformation> result)> QueryDirectory(object handle, string fileName, FileInformationClass informationClass, CancellationToken cancellationToken)
        {
            QueryDirectoryRequest request = new QueryDirectoryRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)m_client.MaxTransactSize / BytesPerCredit);
            request.FileInformationClass = informationClass;
            request.Reopen = true;
            request.FileId = (FileID)handle;
            request.OutputBufferLength = m_client.MaxTransactSize;
            request.FileName = fileName;

            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                var result = new List<QueryDirectoryFileInformation>();
                while (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryDirectoryResponse)
                {
                    var page = ((QueryDirectoryResponse)response).GetFileInformationList(informationClass);
                    result.AddRange(page);
                    request.Reopen = false;
                    await TrySendCommandAsync(request, cancellationToken);
                    response = m_client.WaitForCommand(request.MessageID);
                }
                return (response.Header.Status, result);
            }

            return (NTStatus.STATUS_INVALID_SMB, Enumerable.Empty<QueryDirectoryFileInformation>());
        }

        public async Task<(NTStatus status, FileInformation result)> GetFileInformationAsync(object handle, FileInformationClass informationClass, CancellationToken cancellationToken)
        {
            QueryInfoRequest request = new QueryInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                FileInformation result = null;
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetFileInformation(informationClass);
                }
                return (response.Header.Status, result);
            }

            return (NTStatus.STATUS_INVALID_SMB, null);
        }

        public async Task<NTStatus> SetFileInformationAsync(object handle, FileInformation information, CancellationToken cancellationToken)
        {
            SetInfoRequest request = new SetInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = information.FileInformationClass;
            request.FileId = (FileID)handle;
            request.SetFileInformation(information);

            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<(NTStatus status, FileSystemInformation result)> GetFileSystemInformationAsync(FileSystemInformationClass informationClass, CancellationToken cancellationToken)
        {
            FileSystemInformation result = null;
            var(status, fileHandle, _) = await CreateFile(String.Empty, (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY | (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE, 0, ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FILE_OPEN, CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE, null, cancellationToken);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return (status, result);
            }

            var (aStatus, aResult) = await GetFileSystemInformationAsync(fileHandle, informationClass, cancellationToken);
            await CloseFileAsync(fileHandle, cancellationToken);
            return (aStatus, aResult);
        }

        public async Task<(NTStatus status, FileSystemInformation result)> GetFileSystemInformationAsync(object handle, FileSystemInformationClass informationClass, CancellationToken cancellationToken)
        {
            QueryInfoRequest request = new QueryInfoRequest();
            request.InfoType = InfoType.FileSystem;
            request.FileSystemInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                FileSystemInformation result = null;
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetFileSystemInformation(informationClass);
                }
                return (response.Header.Status, result);
            }

            return (NTStatus.STATUS_INVALID_SMB, null);
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NotImplementedException();
        }

        public async Task<(NTStatus status, SecurityDescriptor result)> GetSecurityInformation(object handle, SecurityInformation securityInformation, CancellationToken cancellationToken)
        {
            SecurityDescriptor result = null;
            QueryInfoRequest request = new QueryInfoRequest();
            request.InfoType = InfoType.Security;
            request.SecurityInformation = securityInformation;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetSecurityInformation();
                }
                return (response.Header.Status, result);
            }

            return (NTStatus.STATUS_INVALID_SMB, result);
        }

        public Task<NTStatus> SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            return Task.FromResult(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            throw new NotImplementedException();
        }

        public NTStatus Cancel(object ioRequest)
        {
            throw new NotImplementedException();
        }

        public async Task<(NTStatus status, byte[] output)> DeviceIOControl(object handle, uint ctlCode, byte[] input, int maxOutputLength, CancellationToken cancellationToken)
        {
            byte[] output = null;
            IOCtlRequest request = new IOCtlRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxOutputLength / BytesPerCredit);
            request.CtlCode = ctlCode;
            request.IsFSCtl = true;
            request.FileId = (FileID)handle;
            request.Input = input;
            request.MaxOutputResponse = (uint)maxOutputLength;
            await TrySendCommandAsync(request, cancellationToken);
            SMB2Command response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if ((response.Header.Status == NTStatus.STATUS_SUCCESS || response.Header.Status == NTStatus.STATUS_BUFFER_OVERFLOW) && response is IOCtlResponse)
                {
                    output = ((IOCtlResponse)response).Output;
                }
                return (response.Header.Status, output);
            }

            return (NTStatus.STATUS_INVALID_SMB, output);
        }

        public async Task<NTStatus> DisconnectAsync()
        {
            TreeDisconnectRequest request = new TreeDisconnectRequest();
            await TrySendCommandAsync(request, CancellationToken.None);
            SMB2Command response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        private Task TrySendCommandAsync(SMB2Command request, CancellationToken cancellationToken)
        {
            request.Header.TreeID = m_treeID;
            return m_client.TrySendCommandAsync(request, m_encryptShareData, cancellationToken);
        }

        public uint MaxReadSize
        {
            get
            {
                return m_client.MaxReadSize;
            }
        }

        public uint MaxWriteSize
        {
            get
            {
                return m_client.MaxWriteSize;
            }
        }

        private static FileStatus ToFileStatus(CreateAction createAction)
        {
            switch (createAction)
            {
                case CreateAction.FILE_SUPERSEDED:
                    return FileStatus.FILE_SUPERSEDED;
                case CreateAction.FILE_OPENED:
                    return FileStatus.FILE_OPENED;
                case CreateAction.FILE_CREATED:
                    return FileStatus.FILE_CREATED;
                case CreateAction.FILE_OVERWRITTEN:
                    return FileStatus.FILE_OVERWRITTEN;
                default:
                    return FileStatus.FILE_OPENED;
            }
        }
    }
}
