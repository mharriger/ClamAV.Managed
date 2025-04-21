/*
 * ClamAV.Managed - Managed bindings for ClamAV
 * Copyright (C) 2011, 2013-2014, 2016 Rupert Muchembled
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
using System.Runtime.InteropServices;

namespace ClamAV.Managed
{
    /// <summary>
    /// Option flags for performing scans.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ScanOptions
    {
        /// <summary>
        /// General scanning options.
        /// </summary>
        public uint General;

        /// <summary>
        /// Parsing capabilities options.
        /// </summary>
        public uint Parse;

        /// <summary>
        /// Heuristic alerting options.
        /// </summary>
        public uint Heuristic;

        /// <summary>
        /// Mail scanning options.
        /// </summary>
        public uint Mail;

        /// <summary>
        /// Development options.
        /// </summary>
        public uint Dev;

        /// <summary>
        /// General scan option flags
        /// </summary>
        [Flags]
        public enum GeneralOptions : uint
        {
            /// <summary>
            /// No options specified.
            /// </summary>
            None = 0x0,

            /// <summary>
            /// Scan in all-match mode.
            /// </summary>
            AllMatches = 0x1,

            /// <summary>
            /// Collect metadata (--gen-json).
            /// </summary>
            CollectMetadata = 0x2,

            /// <summary>
            /// Enable heuristic alerts.
            /// </summary>
            Heuristics = 0x4,

            /// <summary>
            /// Allow heuristic match to take precedence.
            /// </summary>
            HeuristicPrecedence = 0x8,

            /// <summary>
            /// Scanner will not have read access to files.
            /// </summary>
            Unprivileged = 0x10,

            /// <summary>
            /// Store URLs found in HTML a and form tags when recording JSON metadata.
            /// </summary>
            StoreHtmlUrls = 0x20,
        }

        /// <summary>
        /// Parsing capabilities options.
        /// </summary>
        [Flags]
        public enum ParseOptions : uint
        {
            /// <summary>
            /// No parsing options specified.
            /// </summary>
            None = 0x0,

            /// <summary>
            /// Transparently scan various archive formats.
            /// </summary>
            Archive = 0x1,

            /// <summary>
            /// Enable support for ELF executable files.
            /// </summary>
            ELF = 0x2,

            /// <summary>
            /// Scan Adobe PDF files.
            /// </summary>
            PDF = 0x4,

            /// <summary>
            /// Enable scanning of SWF files.
            /// </summary>
            SWF = 0x8,

            /// <summary>
            /// Scan HWP3 document files.
            /// </summary>
            HWP3 = 0x10,

            /// <summary>
            /// Scan XML-based document files.
            /// </summary>
            XMLDocs = 0x20,

            /// <summary>
            /// Scan mail files.
            /// </summary>
            Mail = 0x40,

            /// <summary>
            /// Scan OLE2 containers, including Microsoft Office files and Windows Installer packages.
            /// </summary>
            OLE2 = 0x80,

            /// <summary>
            /// Enable HTML normalisation (including ScrEnc decryption).
            /// </summary>
            HTML = 0x100,

            /// <summary>
            /// Enable deep scanning and unpacking of Portable Executable files.
            /// </summary>
            PE = 0x200,

            /// <summary>
            /// Enable scanning of OneNote files.
            /// </summary>
            OneNote = 0x400,

            /// <summary>
            /// Enable parsing images (graphics).
            /// </summary>
            Image = 0x800,

            /// <summary>
            /// Enable image fuzzy hash calculation.
            /// </summary>
            ImageFuzzyHash = 0x1000,

            /// <summary>
            /// Enable all parsing options.
            /// </summary>
            All = ~0u
        }

        /// <summary>
        /// Heuristic alerting options.
        /// </summary>
        [Flags]
        public enum HeuristicOptions : uint
        {
            /// <summary>
            /// No heuristic options specified.
            /// </summary>
            None = 0x0,

            /// <summary>
            /// Alert on broken PE and broken ELF files.
            /// </summary>
            Broken = 0x2,

            /// <summary>
            /// Alert when files exceed scan limits (filesize, max scansize, or max recursion depth).
            /// </summary>
            ExceedsMax = 0x4,

            /// <summary>
            /// Always block SSL mismatches in URLs.
            /// </summary>
            PhishingSSLMismatch = 0x8,

            /// <summary>
            /// Always block cloaked URLs.
            /// </summary>
            PhishingCloak = 0x10,

            /// <summary>
            /// OLE2 files containing VBA macros will be marked as infected.
            /// </summary>
            Macros = 0x20,

            /// <summary>
            /// Detect encrypted archives as viruses.
            /// </summary>
            EncryptedArchive = 0x40,

            /// <summary>
            /// Alert if a document is encrypted (pdf, docx, etc).
            /// </summary>
            EncryptedDoc = 0x80,

            /// <summary>
            /// Detect partition intersections in raw DMGs using heuristics.
            /// </summary>
            PartitionIntersection = 0x100,

            /// <summary>
            /// Enable the DLP module to scan for sensitive data.
            /// </summary>
            Structured = 0x200,

            /// <summary>
            /// Search for SSNs structured as xx-yy-zzzz.
            /// </summary>
            StructuredSSNNormal = 0x400,

            /// <summary>
            /// Search for SSNs structured as xxyyzzzz.
            /// </summary>
            StructuredSSNStripped = 0x800,

            /// <summary>
            /// Alert when detecting credit card numbers.
            /// </summary>
            StructuredCC = 0x1000,

            /// <summary>
            /// Alert if a file does not match the identified file format (JPEG, TIFF, GIF, PNG).
            /// </summary>
            BrokenMedia = 0x2000,
        }

        /// <summary>
        /// Mail scanning options.
        /// </summary>
        [Flags]
        public enum MailOptions : uint
        {
            /// <summary>
            /// No mail options specified.
            /// </summary>
            None = 0x0,

            /// <summary>
            /// Scan RFC1341 messages split over many emails.
            /// </summary>
            PartialMessage = 0x1,
        }

        /// <summary>
        /// Development options.
        /// </summary>
        [Flags]
        public enum DevOptions : uint
        {
            /// <summary>
            /// No development options specified.
            /// </summary>
            None = 0x0,

            /// <summary>
            /// Enables hash output in sha-collect builds - for internal use only.
            /// </summary>
            CollectSHA = 0x1,

            /// <summary>
            /// Collect performance timings.
            /// </summary>
            CollectPerformanceInfo = 0x2,
        }

        /// <summary>
        /// Alias for a recommended set of scan options with sensible defaults.
        /// </summary>
        public static ScanOptions StandardOptions
        {
            get
            {
                return new ScanOptions
                {
                    Parse = (uint)ParseOptions.All
                };
            }
        }
    }
}
