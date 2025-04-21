/*
 * ClamAV.Managed.Tests - Managed bindings for ClamAV - unit test suite
 * Copyright (C) 2011, 2013-2014 Rupert Muchembled
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

using NUnit.Framework;
using NUnit.Framework.Constraints;

namespace ClamAV.Managed.Tests
{
    /// <summary>
    /// Test getting and setting ClamEngine property values.
    /// </summary>
    [TestFixture]
    public class ClamEnginePropertyTests
    {
        private ClamEngine _clamEngine;

        [SetUp]
        public void SetUpClamEngine()
        {
            if (!TestHelpers.NativeLibraryExists())
                Assert.Ignore("libclamav dynamic library is missing from the unit test binary directory.");

            _clamEngine = new ClamEngine();
        }

        [TearDown]
        public void TearDownClamEngine()
        {
            if (_clamEngine != null)
            {
                _clamEngine.Dispose();
                _clamEngine = null;
            }
        }

        [Test]
        public void VersionPropertyIsNotNullOrEmpty()
        {
            var version = ClamEngine.Version;

            Assert.That(version, Is.Not.Null.And.Not.Empty);
        }

        [Test]
        public void DatabaseDirectoryPropertyIsNotNullOrEmpty()
        {
            var databaseDirectory = _clamEngine.DatabaseDirectory;

            Assert.That(databaseDirectory, Is.Not.Null.And.Not.Empty);
        }

        [Test]
        public void MaxScanSizeIsReadWritable()
        {
            ulong value = 1024 * 123;

            _clamEngine.MaxScanSize = value;

            Assert.That(_clamEngine.MaxScanSize, Is.EqualTo(value));
        }

        [Test]
        public void MaxFileSizeIsReadWritable()
        {
            ulong value = 1024 * 124;

            _clamEngine.MaxFileSize = value;

            Assert.That(_clamEngine.MaxFileSize, Is.EqualTo(value));
        }

        [Test]
        public void MaxRecursionIsReadWritable()
        {
            uint value = 125;

            _clamEngine.MaxRecursion = value;

            Assert.That(_clamEngine.MaxRecursion, Is.EqualTo(value));
        }

        [Test]
        public void MaxFilesIsReadWritableIsReadWritable()
        {
            uint value = 126;

            _clamEngine.MaxFiles = value;

            Assert.That(_clamEngine.MaxFiles, Is.EqualTo(value));
        }

        [Test]
        public void MinCCCountIsReadWritableIsReadWritable()
        {
            uint value = 3;

            _clamEngine.MinCCCount = value;

            Assert.That(_clamEngine.MinCCCount, Is.EqualTo(value));
        }

        [Test]
        public void MinSSNCountIsReadWritableIsReadWritable()
        {
            uint value = 4;

            _clamEngine.MinSSNCount = value;

            Assert.That(_clamEngine.MinSSNCount, Is.EqualTo(value));
        }

        [Test]
        public void PuaCategoriesIsReadWritable()
        {
            string value = "xyz";

            _clamEngine.PuaCategories = value;

            Assert.That(_clamEngine.PuaCategories, Is.EqualTo(value));
        }

        [Test]
        public void ACOnlyIsReadWritable()
        {
            uint value = 1;

            _clamEngine.ACOnly = value;

            Assert.That(_clamEngine.ACOnly, Is.EqualTo(value));
        }

        [Test]
        public void ACMinDepthIsReadWritable()
        {
            uint value = 4;

            _clamEngine.ACMinDepth = value;

            Assert.That(_clamEngine.ACMinDepth, Is.EqualTo(value));
        }

        [Test]
        public void ACMaxDepthIsReadWritable()
        {
            uint value = 5;

            _clamEngine.ACMaxDepth = value;

            Assert.That(_clamEngine.ACMaxDepth, Is.EqualTo(value));
        }

        [Test]
        public void TempDirIsReadWritable()
        {
            string value = @"E:\Temp";

            _clamEngine.TempDir = value;

            Assert.That(_clamEngine.TempDir, Is.EqualTo(value));
        }

        [Test]
        public void KeepTempFilesIsReadWritable()
        {
            uint value = 0;

            _clamEngine.KeepTempFiles = value;

            Assert.That(_clamEngine.KeepTempFiles, Is.EqualTo(value));
        }

        [Test]
        public void BytecodeSecurityIsReadWritable()
        {
            var value = BytecodeSecurity.TrustAll;

            _clamEngine.BytecodeSecurity = value;

            Assert.That(_clamEngine.BytecodeSecurity, Is.EqualTo(value));
        }

        [Test]
        public void BytecodeTimeoutIsReadWritable()
        {
            uint value = 3600;

            _clamEngine.BytecodeTimeout = value;

            Assert.That(_clamEngine.BytecodeTimeout, Is.EqualTo(value));
        }

        [Test]
        public void BytecodeModeIsReadWritable()
        {
            var value = BytecodeMode.Interpreter;

            _clamEngine.BytecodeMode = value;

            Assert.That(_clamEngine.BytecodeMode, Is.EqualTo(value));
        }

        [Test]
        public void MaxEmbeddedPEIsReadWritable()
        {
            ulong value = 1024;

            _clamEngine.MaxEmbeddedPE = value;

            Assert.That(_clamEngine.MaxEmbeddedPE, Is.EqualTo(value));
        }

        [Test]
        public void MaxHtmlNormalizeIsReadWritable()
        {
            ulong value = 1536;

            _clamEngine.MaxHtmlNormalize = value;

            Assert.That(_clamEngine.MaxHtmlNormalize, Is.EqualTo(value));
        }

        [Test]
        public void MaxHtmlNoTagsIsReadWritable()
        {
            ulong value = 2048;

            _clamEngine.MaxHtmlNoTags = value;

            Assert.That(_clamEngine.MaxHtmlNoTags, Is.EqualTo(value));
        }

        [Test]
        public void MaxScriptNormalizeIsReadWritable()
        {
            ulong value = 4096;

            _clamEngine.MaxScriptNormalize = value;

            Assert.That(_clamEngine.MaxScriptNormalize, Is.EqualTo(value));
        }

        [Test]
        public void MaxZipTypeRcgIsReadWritable()
        {
            ulong value = 8192;

            _clamEngine.MaxZipTypeRcg = value;

            Assert.That(_clamEngine.MaxZipTypeRcg, Is.EqualTo(value));
        }
        
        [Test]
        public void ForceToDiskIsReadWritable()
        {
            var value = true;

            _clamEngine.ForceToDisk = value;

            Assert.That(_clamEngine.ForceToDisk, Is.EqualTo(value));
        }

        [Test]
        public void DisableCacheIsReadWritable()
        {
            var value = true;

            _clamEngine.DisableCache = value;

            Assert.That(_clamEngine.DisableCache, Is.EqualTo(value));
        }

        [Test]
        [Ignore("Not implemented in libclamav.dll")]
        public void DisablePeStatsIsReadWritable()
        {
            var value = true;

            _clamEngine.DisablePeStats = value;

            Assert.That(_clamEngine.DisablePeStats, Is.EqualTo(value));
        }

        [Test]
        public void StatsTimeoutIsReadWritable()
        {
            uint value = 123;

            _clamEngine.StatsTimeout = value;

            Assert.That(_clamEngine.StatsTimeout, Is.EqualTo(value));
        }

        [Test]
        public void MaxPartitionsIsReadWritable()
        {
            uint value = 9;

            _clamEngine.MaxPartitions = value;

            Assert.That(_clamEngine.MaxPartitions, Is.EqualTo(value));
        }

        [Test]
        public void MaxIconSpeIsReadWritable()
        {
            uint value = 7;

            _clamEngine.MaxIconSpe = value;

            Assert.That(_clamEngine.MaxIconSpe, Is.EqualTo(value));
        }

        [Test]
        public void MaxRecHwp3IsReadWritable()
        {
            uint value = 5;

            _clamEngine.MaxRecHwp3 = value;

            Assert.That(_clamEngine.MaxRecHwp3, Is.EqualTo(value));
        }

        [Test]
        public void TimeLimitIsReadWritable()
        {
            uint value = 119;

            _clamEngine.TimeLimit = value;

            Assert.That(_clamEngine.TimeLimit, Is.EqualTo(value));
        }

        [Test]
        public void PcreMatchLimitIsReadWritable()
        {
            uint value = 17;

            _clamEngine.PcreMatchLimit = value;

            Assert.That(_clamEngine.PcreMatchLimit, Is.EqualTo(value));
        }

        [Test]
        public void PcreRecMatchLimitIsReadWritable()
        {
            uint value = 119;

            _clamEngine.PcreRecMatchLimit = value;

            Assert.That(_clamEngine.PcreRecMatchLimit, Is.EqualTo(value));
        }

        [Test]
        public void PcreMaxFilesizeIsReadWritable()
        {
            ulong value = 17;

            _clamEngine.PcreMaxFilesize = value;

            Assert.That(_clamEngine.PcreMaxFilesize, Is.EqualTo(value));
        }

        [Test]
        [Ignore("Not implemented in libclamav.dll")]
        public void DisablePeCertsIsReadWritable()
        {
            var value = true;

            _clamEngine.DisablePeCerts = value;

            Assert.That(_clamEngine.DisablePeCerts, Is.EqualTo(value));
        }

        [Test]
        [Ignore("Not implemented in libclamav.dll")]
        public void PeDumpCertsIsReadWritable()
        {
            var value = true;

            _clamEngine.PeDumpCerts = value;

            Assert.That(_clamEngine.PeDumpCerts, Is.EqualTo(value));
        }
    }
}
