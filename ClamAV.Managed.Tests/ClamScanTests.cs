/*
 * ClamAV.Managed.Tests - Managed bindings for ClamAV - unit test suite
 * Copyright (C) 2011, 2013-2014, 2025 Rupert Muchembled
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
using System.IO;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using NUnit.Framework.Constraints;

namespace ClamAV.Managed.Tests
{
    /// <summary>
    /// Test scanning functionality of the ClamAV engine.
    /// </summary>
    [TestFixture]
    public class ClamScanTests
    {
        private ClamEngine _clamEngine;
        private string _testFilesPath;
        private string _samplesPath;

        [SetUp]
        public void SetUp()
        {
            if (!TestHelpers.NativeLibraryExists())
                Assert.Ignore("libclamav dynamic library is missing from the unit test binary directory.");

            if (!TestHelpers.TestFilesDirectoryExists())
                Assert.Ignore("TestFiles directory is missing.");

            _testFilesPath = TestHelpers.TestFilesDirectory;
            _samplesPath = Path.Combine(_testFilesPath, "samples");

            if (!Directory.Exists(_samplesPath))
                Assert.Ignore("Samples directory is missing. Run Scripts/SetUpTestFiles.ps1 first.");

            _clamEngine = new ClamEngine();
            
            // Load the database to ensure proper scanning
            try
            {
                _clamEngine.LoadDatabase(Path.Combine(_testFilesPath, "db"));
            }
            catch (Exception ex)
            {
                Assert.Ignore($"Could not load the test database: {ex.Message}");
            }
        }

        [TearDown]
        public void TearDown()
        {
            if (_clamEngine != null)
            {
                _clamEngine.Dispose();
                _clamEngine = null;
            }
        }

        [Test]
        public void ScanFile_WithCleanFile_ReturnsClean()
        {
            // Arrange
            var cleanFile = Path.Combine(_samplesPath, "clean_text_file.txt");
            
            // Act
            var result = _clamEngine.ScanFile(cleanFile, out string virusName);

            // Assert
            Assert.That(result, Is.EqualTo(ScanResult.Clean));
            Assert.That(virusName, Is.Empty);
        }

        [Test]
        public void ScanFile_WithVirusFile_ReturnsVirus()
        {
            // Arrange
            var virusFile = Path.Combine(_samplesPath, "eicar_test_file.txt");
            
            // Act
            var result = _clamEngine.ScanFile(virusFile, out string virusName);

            // Assert
            Assert.That(result, Is.EqualTo(ScanResult.Virus));
            Assert.That(virusName, Is.Not.Empty);
            Assert.That(virusName, Does.Contain("EICAR"), "The virus name should contain 'EICAR'");
        }

        [Test]
        public void ScanFile_WithBinaryFile_ReturnsClean()
        {
            // Arrange
            var binaryFile = Path.Combine(_samplesPath, "binary_sample.dat");
            
            // Act
            var result = _clamEngine.ScanFile(binaryFile, out string virusName);

            // Assert
            Assert.That(result, Is.EqualTo(ScanResult.Clean));
            Assert.That(virusName, Is.Empty);
        }

        [Test]
        public void ScanDirectory_WithCallback_ProcessesAllFiles()
        {
            // Arrange
            var scannedFiles = new List<string>();
            var scannedResults = new List<ScanResult>();
            var virusNames = new List<string>();

            FileScannedCallback callback = (path, result, virus) => 
            {
                scannedFiles.Add(path);
                scannedResults.Add(result);
                virusNames.Add(virus);
            };

            // Act
            _clamEngine.ScanDirectory(_samplesPath, callback);

            // Assert
            Assert.That(scannedFiles, Is.Not.Empty, "No files were scanned");
            
            // Ensure our EICAR test file was detected
            bool detectedEicar = false;
            for (int i = 0; i < scannedFiles.Count; i++)
            {
                if (scannedFiles[i].Contains("eicar_test_file.txt"))
                {
                    detectedEicar = true;
                    Assert.That(scannedResults[i], Is.EqualTo(ScanResult.Virus), 
                        "EICAR test file should be detected as a virus");
                    Assert.That(virusNames[i], Is.Not.Empty, 
                        "The virus name should not be empty");
                    Assert.That(virusNames[i], Does.Contain("EICAR"), 
                        "The virus name should contain 'EICAR'");
                }
            }
            
            Assert.That(detectedEicar, Is.True, "Scanner did not detect the EICAR test file");
        }

        [Test]
        public void ScanDirectory_WithRecursive_IncludesNestedFiles()
        {
            // Arrange
            var scannedFiles = new List<string>();
            var nestedFileFound = false;

            FileScannedCallback callback = (path, result, virus) => 
            {
                scannedFiles.Add(path);
                if (path.Contains("nested_folder") && path.Contains("nested_clean_file.txt"))
                    nestedFileFound = true;
            };
            
            // Act
            // Scan with recursion
            _clamEngine.ScanDirectory(_samplesPath, ScanOptions.StandardOptions, callback, true, 2);

            // Assert
            Assert.That(nestedFileFound, Is.True, "Nested file was not found during recursive scan");
        }

        [Test]
        public void ScanDirectory_WithNonRecursive_ExcludesNestedFiles()
        {
            // Arrange
            var scannedFiles = new List<string>();
            var nestedFileFound = false;

            FileScannedCallback callback = (path, result, virus) => 
            {
                scannedFiles.Add(path);
                if (path.Contains("nested_folder") && path.Contains("nested_clean_file.txt"))
                    nestedFileFound = true;
            };
            
            // Act
            // Scan without recursion (only main directory)
            _clamEngine.ScanDirectory(_samplesPath, ScanOptions.StandardOptions, callback, false, 1);

            // Assert
            Assert.That(nestedFileFound, Is.False, "Nested file was found during non-recursive scan");
            Assert.That(scannedFiles.All(f => !f.Contains(Path.DirectorySeparatorChar + "nested_folder" + Path.DirectorySeparatorChar)), 
                Is.True, "Files from nested folders were incorrectly included in non-recursive scan");
        }
    }
}