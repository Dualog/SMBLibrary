/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Utilities;

namespace SMBLibrary
{
    public delegate void OnNotifyChangeCompleted(NTStatus status, byte[] buffer, object context);

    /// <summary>
    /// A file store (a.k.a. object store) interface to allow access to a file system or a named pipe in an NT-like manner dictated by the SMB protocol.
    /// </summary>
    public interface INTFileStore
    {
        Task<(NTStatus status, object handle, FileStatus fileStatus)> CreateFile(string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext, CancellationToken cancellationToken);

        Task<NTStatus> CloseFileAsync(object handle, CancellationToken cancellationToken);

        Task<(NTStatus status, byte[] data)> ReadFileAsync(object handle, long offset, int maxCount, CancellationToken cancellationToken);

        Task<(NTStatus status, int numberOfBytesWritten)> WriteFileAsync(object handle, long offset, byte[] data, CancellationToken cancellationToken);

        Task<NTStatus> FlushFileBuffersAsync(object handle, CancellationToken cancellationToken);

        NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock);

        NTStatus UnlockFile(object handle, long byteOffset, long length);

        Task<(NTStatus status, IEnumerable<QueryDirectoryFileInformation> result)> QueryDirectory(object handle, string fileName, FileInformationClass informationClass, CancellationToken cancellationToken);

        Task<(NTStatus status, FileInformation result)> GetFileInformationAsync(object handle, FileInformationClass informationClass, CancellationToken cancellationToken);

        Task<NTStatus> SetFileInformationAsync(object handle, FileInformation information, CancellationToken cancellationToken);

        Task<(NTStatus status, FileSystemInformation result)> GetFileSystemInformationAsync(FileSystemInformationClass informationClass, CancellationToken cancellationToken);

        Task<(NTStatus status, FileSystemInformation result)> GetFileSystemInformationAsync(object handle, FileSystemInformationClass informationClass, CancellationToken cancellationToken);

        Task<(NTStatus status, SecurityDescriptor result)> GetSecurityInformation(object handle, SecurityInformation securityInformation, CancellationToken cancellationToken);

        Task<NTStatus> SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor);

        /// <summary>
        /// Monitor the contents of a directory (and its subdirectories) by using change notifications.
        /// When something changes within the directory being watched this operation is completed.
        /// </summary>
        /// <returns>
        /// STATUS_PENDING - The directory is being watched, change notification will be provided using callback method.
        /// STATUS_NOT_SUPPORTED - The underlying object store does not support change notifications.
        /// STATUS_INVALID_HANDLE - The handle supplied is invalid.
        /// </returns>
        NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context);

        NTStatus Cancel(object ioRequest);

        Task<(NTStatus status, byte[] output)> DeviceIOControl(object handle, uint ctlCode, byte[] input, int maxOutputLength, CancellationToken cancellationToken);
    }
}
