/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SMBLibrary.RPC;
using SMBLibrary.Services;
using Utilities;

namespace SMBLibrary
{
    public class NamedPipeStore : INTFileStore
    {
        private List<RemoteService> m_services;

        public NamedPipeStore(List<RemoteService> services)
        {
            m_services = services;
        }

        public Task<(NTStatus status, object handle, FileStatus fileStatus)> CreateFile(string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext, CancellationToken cancellationToken)
        {
            var fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
            // It is possible to have a named pipe that does not use RPC (e.g. MS-WSP),
            // However this is not currently needed by our implementation.
            RemoteService service = GetService(path);
            if (service != null)
            {
                // All instances of a named pipe share the same pipe name, but each instance has its own buffers and handles,
                // and provides a separate conduit for client/server communication.
                RPCPipeStream stream = new RPCPipeStream(service);
                var handle = new FileHandle(path, false, stream, false);
                fileStatus = FileStatus.FILE_OPENED;
                return Task.FromResult<(NTStatus, object, FileStatus)>((NTStatus.STATUS_SUCCESS, handle, fileStatus));
            }

            return Task.FromResult<(NTStatus, object, FileStatus)>((NTStatus.STATUS_OBJECT_PATH_NOT_FOUND, null, fileStatus));
        }

        public Task<NTStatus> CloseFileAsync(object handle, CancellationToken cancellationToken)
        {
            FileHandle fileHandle = (FileHandle)handle;
            if (fileHandle.Stream != null)
            {
                fileHandle.Stream.Close();
            }
            return Task.FromResult(NTStatus.STATUS_SUCCESS);
        }

        private RemoteService GetService(string path)
        {
            if (path.StartsWith(@"\"))
            {
                path = path.Substring(1);
            }

            foreach (RemoteService service in m_services)
            {
                if (String.Equals(path, service.PipeName, StringComparison.OrdinalIgnoreCase))
                {
                    return service;
                }
            }
            return null;
        }

        public Task<(NTStatus status, byte[] data)> ReadFileAsync(object handle, long offset, int maxCount, CancellationToken cancellationToken)
        {
            Stream stream = ((FileHandle)handle).Stream;
            var data = new byte[maxCount];
            int bytesRead = stream.Read(data, 0, maxCount);
            if (bytesRead < maxCount)
            {
                // EOF, we must trim the response data array
                data = ByteReader.ReadBytes(data, 0, bytesRead);
            }

            return Task.FromResult((NTStatus.STATUS_SUCCESS, data));
        }

        public Task<(NTStatus status, int numberOfBytesWritten)> WriteFileAsync(object handle, long offset, byte[] data, CancellationToken cancellationToken)
        {
            Stream stream = ((FileHandle)handle).Stream;
            stream.Write(data, 0, data.Length);
            return Task.FromResult((NTStatus.STATUS_SUCCESS, data.Length));
        }

        public Task<NTStatus> FlushFileBuffersAsync(object handle, CancellationToken cancellationToken)
        {
            FileHandle fileHandle = (FileHandle)handle;
            if (fileHandle.Stream != null)
            {
                fileHandle.Stream.FlushAsync(cancellationToken);
            }
            return Task.FromResult(NTStatus.STATUS_SUCCESS);
        }

        public NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus UnlockFile(object handle, long byteOffset, long length)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public async Task<(NTStatus status, byte[] output)> DeviceIOControl(object handle, uint ctlCode, byte[] input, int maxOutputLength, CancellationToken cancellationToken)
        {
            byte[] output = null;
            if (ctlCode == (uint)IoControlCode.FSCTL_PIPE_WAIT)
            {
                PipeWaitRequest request;
                try
                {
                    request = new PipeWaitRequest(input, 0);
                }
                catch
                {
                    return (NTStatus.STATUS_INVALID_PARAMETER, output);
                }

                RemoteService service = GetService(request.Name);
                if (service == null)
                {
                    return (NTStatus.STATUS_OBJECT_NAME_NOT_FOUND, output);
                }

                output = new byte[0];
                return (NTStatus.STATUS_SUCCESS, output);
            }
            else if (ctlCode == (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE)
            {
                var (writeStatus, numberOfBytesWritten) = await WriteFileAsync(handle, 0, input, cancellationToken);
                if (writeStatus != NTStatus.STATUS_SUCCESS)
                {
                    return (writeStatus, output);
                }
                int messageLength = ((RPCPipeStream)((FileHandle)handle).Stream).MessageLength;

                NTStatus readStatus;                                
                (readStatus, output) = await ReadFileAsync(handle, 0, maxOutputLength, cancellationToken);
                if (readStatus != NTStatus.STATUS_SUCCESS)
                {
                    return (readStatus, output);
                }

                if (output.Length < messageLength)
                {
                    return (NTStatus.STATUS_BUFFER_OVERFLOW, output);
                }
                else
                {
                    return (NTStatus.STATUS_SUCCESS, output);
                }
            }

            return (NTStatus.STATUS_NOT_SUPPORTED, output);
        }

        public Task<(NTStatus status, IEnumerable<QueryDirectoryFileInformation> result)> QueryDirectory(object handle, string fileName, FileInformationClass informationClass, CancellationToken cancellationToken)
        {
            return Task.FromResult((NTStatus.STATUS_NOT_SUPPORTED, Enumerable.Empty<QueryDirectoryFileInformation>()));
        }

        public Task<(NTStatus status, FileInformation result)> GetFileInformationAsync(object handle, FileInformationClass informationClass, CancellationToken cancellationToken)
        {
            switch (informationClass)
            {
                case FileInformationClass.FileBasicInformation:
                    {
                        FileBasicInformation information = new FileBasicInformation();
                        information.FileAttributes = FileAttributes.Temporary;
                        return Task.FromResult<(NTStatus, FileInformation)>((NTStatus.STATUS_SUCCESS, information));
                    }
                case FileInformationClass.FileStandardInformation:
                    {
                        FileStandardInformation information = new FileStandardInformation();
                        information.DeletePending = false;
                        return Task.FromResult<(NTStatus, FileInformation)>((NTStatus.STATUS_SUCCESS, information));
                    }
                case FileInformationClass.FileNetworkOpenInformation:
                    {
                        FileNetworkOpenInformation information = new FileNetworkOpenInformation();
                        information.FileAttributes = FileAttributes.Temporary;
                        return Task.FromResult<(NTStatus, FileInformation)>((NTStatus.STATUS_SUCCESS, information));
                    }
                default:
                    return Task.FromResult<(NTStatus, FileInformation)>((NTStatus.STATUS_INVALID_INFO_CLASS, null));
            }
        }

        public Task<NTStatus> SetFileInformationAsync(object handle, FileInformation information, CancellationToken cancellationToken)
        {
            return Task.FromResult(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public Task<(NTStatus status, FileSystemInformation result)> GetFileSystemInformationAsync(object handle, FileSystemInformationClass informationClass, CancellationToken cancellationToken)
        {
            return Task.FromResult<(NTStatus, FileSystemInformation)>((NTStatus.STATUS_NOT_SUPPORTED, null));
        }

        public Task<(NTStatus status, FileSystemInformation result)> GetFileSystemInformationAsync(FileSystemInformationClass informationClass, CancellationToken cancellationToken)
        {
            return Task.FromResult<(NTStatus, FileSystemInformation)>((NTStatus.STATUS_NOT_SUPPORTED, null));
        }

        public Task<NTStatus> SetFileSystemInformation(FileSystemInformation information)
        {
            return Task.FromResult(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public Task<(NTStatus status, SecurityDescriptor result)> GetSecurityInformation(object handle, SecurityInformation securityInformation, CancellationToken cancellationToken)
        {
            return Task.FromResult<(NTStatus, SecurityDescriptor)>((NTStatus.STATUS_NOT_SUPPORTED, null));
        }

        public Task<NTStatus> SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            return Task.FromResult(NTStatus.STATUS_NOT_SUPPORTED);
        }

        public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            ioRequest = null;
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus Cancel(object ioRequest)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }
    }
}
