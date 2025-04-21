/*
 * ClamAV.Managed.Async - Managed bindings for ClamAV - Asynchronous extensions
 * Copyright (C) 2011, 2013-2014, 2021 Rupert Muchembled
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace ClamAV.Managed.Async
{
    /// <summary>
    /// Provides methods for asynchronously performing virus scans.
    /// </summary>
    public static class ClamEngineExtensions
    {
        /// <summary>
        /// Asynchronously load databases from the default hardcoded path using standard options.
        /// </summary>
        /// <param name="engine">ClamAV engine instance.</param>
        /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task LoadDatabaseAsync(this ClamEngine engine, CancellationToken cancellationToken = default)
        {
            return Task.Run(engine.LoadDatabase, cancellationToken);
        }

        /// <summary>
        /// Asynchronously load databases from the default hardcoded path using custom options.
        /// </summary>
        /// <param name="engine">ClamAV engine instance.</param>
        /// <param name="options">Options with which to load the database.</param>
        /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task LoadDatabaseAsync(this ClamEngine engine, LoadOptions options, CancellationToken cancellationToken = default)
        {
            return Task.Run(() => engine.LoadDatabase(options), cancellationToken);
        }

        /// <summary>
        /// Asynchronously load databases from a custom path using standard options.
        /// </summary>
        /// <param name="engine">ClamAV engine instance.</param>
        /// <param name="path">Path to the database file or a directory containing database files.</param>
        /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task LoadDatabaseAsync(this ClamEngine engine, string path, CancellationToken cancellationToken = default)
        {
            return Task.Run(() => engine.LoadDatabase(path), cancellationToken);
        }

        /// <summary>
        /// Asynchronously loads a database file or directory into the engine.
        /// </summary>
        /// <param name="engine">ClamAV engine instance.</param>
        /// <param name="path">Path to the database file or a directory containing database files.</param>
        /// <param name="options">Options with which to load the database.</param>
        /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task LoadDatabaseAsync(this ClamEngine engine, string path, LoadOptions options, CancellationToken cancellationToken = default)
        {
            return Task.Run(() => engine.LoadDatabase(path, options), cancellationToken);
        }

        /// <summary>
        /// Asynchronously scans a file for viruses with the default scan options.
        /// </summary>
        /// <param name="engine">ClamAV engine instance.</param>
        /// <param name="path">Path to the file to be scanned.</param>
        /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
        /// <returns>The task object representing the asynchronous operation. The Result property on the task returns a scan result.</returns>
        public static Task<FileScanResult> ScanFileAsync(this ClamEngine engine, string path, CancellationToken cancellationToken = default)
        {
            return ScanFileAsync(engine, path, ScanOptions.StandardOptions, cancellationToken);
        }

        /// <summary>
        /// Asynchronously scans a file for viruses.
        /// </summary>
        /// <param name="engine">ClamAV engine instance.</param>
        /// <param name="path">Path to the file to be scanned.</param>
        /// <param name="options">Scan options.</param>
        /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
        /// <returns>The task object representing the asynchronous operation. The Result property on the task returns a scan result.</returns>
        public static Task<FileScanResult> ScanFileAsync(this ClamEngine engine, string path, ScanOptions options, CancellationToken cancellationToken = default)
        {
            return Task.Run(() => 
            {
                var scanResult = engine.ScanFile(path, options, out string virusName);
                return new FileScanResult(path, scanResult == ScanResult.Virus, virusName);
            }, cancellationToken);
        }

        /// <summary>
        /// Asynchronously scans a directory for viruses with the default scan options, recursing into subdirectories.
        /// </summary>
        /// <param name="engine">ClamAV engine instance.</param>
        /// <param name="path">Path to scan.</param>
        /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
        /// <returns>The task object representing the asynchronous operation. The Result property on the task returns the scan results.</returns>
        public static Task<IEnumerable<FileScanResult>> ScanDirectoryAsync(this ClamEngine engine, string path, CancellationToken cancellationToken = default)
        {
            return ScanDirectoryAsync(engine, path, ScanOptions.StandardOptions, true, 0, cancellationToken);
        }

        /// <summary>
        /// Asynchronously scans a directory for viruses, recursing into subdirectories.
        /// </summary>
        /// <param name="engine">ClamAV engine instance.</param>
        /// <param name="path">Path to scan.</param>
        /// <param name="options">Scan options.</param>
        /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
        /// <returns>The task object representing the asynchronous operation. The Result property on the task returns the scan results.</returns>
        public static Task<IEnumerable<FileScanResult>> ScanDirectoryAsync(this ClamEngine engine, string path, ScanOptions options, CancellationToken cancellationToken = default)
        {
            return ScanDirectoryAsync(engine, path, options, true, 0, cancellationToken);
        }

        /// <summary>
        /// Asynchronously scans a directory for viruses, optionally recursing into subdirectories.
        /// </summary>
        /// <param name="engine">ClamAV engine instance.</param>
        /// <param name="path">Path to scan.</param>
        /// <param name="options">Scan options.</param>
        /// <param name="recurse">Whether to enter subdirectories.</param>
        /// <param name="maxDepth">Maximum depth to scan, or zero for unlimited.</param>
        /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
        /// <returns>The task object representing the asynchronous operation. The Result property on the task returns the scan results.</returns>
        public static Task<IEnumerable<FileScanResult>> ScanDirectoryAsync(
            this ClamEngine engine, 
            string path, 
            ScanOptions options, 
            bool recurse, 
            int maxDepth, 
            CancellationToken cancellationToken = default)
        {
            return Task.Run(async () => 
            {
                var scanQueue = new Queue<string>();
                
                var pathStack = new Stack<(string path, int depth)>();

                // Push the starting directory onto the stack.
                pathStack.Push((path, 1));

                while (pathStack.Count > 0 && !cancellationToken.IsCancellationRequested)
                {
                    var (currentPath, currentDepth) = pathStack.Pop();

                    var attributes = File.GetAttributes(currentPath);

                    // If we're in a directory, push all files and subdirectories to the stack.
                    if ((attributes & FileAttributes.Directory) == FileAttributes.Directory)
                    {
                        // Check if we're not about to go too deep.
                        if (recurse && (maxDepth == 0 || currentDepth < maxDepth))
                        {
                            foreach (var file in Directory.GetFiles(currentPath))
                            {
                                pathStack.Push((file, currentDepth + 1));
                            }

                            foreach (var directory in Directory.GetDirectories(currentPath))
                            {
                                pathStack.Push((directory, currentDepth + 1));
                            }
                        }
                    }
                    // If this is a file, enqueue it for scanning.
                    else
                    {
                        scanQueue.Enqueue(currentPath);
                    }
                }

                cancellationToken.ThrowIfCancellationRequested();

                var scanTasks = scanQueue.Select(filePath => ScanFileAsync(engine, filePath, options, cancellationToken));
                var scanResults = await Task.WhenAll(scanTasks).ConfigureAwait(false);

                return scanResults.AsEnumerable();
            }, cancellationToken);
        }
    }
}
