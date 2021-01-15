import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open

from pyrdp.mitm.FileMapping import FileMapping


class FileMappingTest(unittest.TestCase):
    def setUp(self):
        self.log = Mock()
        self.outDir = Path("test/")
        self.hash = "testHash"

    @patch("builtins.open", new_callable=mock_open)
    @patch("tempfile.mkstemp")
    @patch("pathlib.Path.mkdir")
    def createMapping(self, mkdir: MagicMock, mkstemp: MagicMock, mock_open_object):
        mkstemp.return_value = (1, str(self.outDir / "tmp" / "tmp_test"))
        mapping = FileMapping.generate("/test", self.outDir, Path("filesystems"), self.log)
        mapping.getHash = Mock(return_value = self.hash)
        return mapping, mkdir, mkstemp, mock_open_object

    def test_generate_createsTempFile(self):
        mapping, mkdir, mkstemp, mock_open_object = self.createMapping()
        mkstemp.return_value = (1, str(self.outDir / "tmp" / "tmp_test"))

        mkdir.assert_called_once_with(exist_ok = True)
        mkstemp.assert_called_once()
        mock_open_object.assert_called_once()

        tmpDir = mkstemp.call_args[0][-1]
        self.assertEqual(tmpDir, self.outDir / "tmp")

    def test_write_setsWritten(self):
        mapping, *_ = self.createMapping()
        self.assertFalse(mapping.written)
        mapping.write(b"data")
        self.assertTrue(mapping.written)

    def test_finalize_removesUnwrittenFiles(self):
        mapping, *_ = self.createMapping()

        with patch("pathlib.Path.unlink", autospec=True) as mock_unlink:
            mapping.finalize()
            self.assertTrue(any(args[0][0] == mapping.dataPath for args in mock_unlink.call_args_list))

    @patch("pathlib.Path.exists", new_callable=lambda: Mock(return_value=True))
    @patch("pathlib.Path.symlink_to")
    @patch("pathlib.Path.mkdir")
    def test_finalize_removesDuplicates(self, *_):
        mapping, *_ = self.createMapping()
        mapping.write(b"data")

        with patch("pathlib.Path.unlink", autospec=True) as mock_unlink:
            mapping.finalize()
            self.assertTrue(any(args[0][0] == mapping.dataPath for args in mock_unlink.call_args_list))

    @patch("pathlib.Path.unlink")
    @patch("pathlib.Path.exists", new_callable=lambda: Mock(return_value=False))
    @patch("pathlib.Path.symlink_to")
    @patch("pathlib.Path.mkdir")
    def test_finalize_movesFileToOutDir(self, *_):
        mapping, *_ = self.createMapping()
        mapping.write(b"data")

        with patch("pathlib.Path.rename") as mock_rename:
            mapping.finalize()
            mock_rename.assert_called_once()
            self.assertEqual(mock_rename.call_args[0][0].parents[0], self.outDir)

    @patch("pathlib.Path.rename")
    @patch("pathlib.Path.unlink")
    @patch("pathlib.Path.exists", new_callable=lambda: Mock(return_value=False))
    def test_finalize_createsSymlink(self, *_):
        mapping, *_ = self.createMapping()
        mapping.write(b"data")

        with patch("pathlib.Path.symlink_to") as mock_symlink_to, patch("pathlib.Path.mkdir", autospec=True) as mock_mkdir:
            mapping.finalize()

            mock_mkdir.assert_called_once()
            mock_symlink_to.assert_called_once()

            self.assertEqual(mock_mkdir.call_args[0][0], mapping.filesystemPath.parents[0])

            # The symlink must be a relative symlink.
            # The symlink is in filesystems/ so the link path will start with '..'.
            self.assertEqual(mock_symlink_to.call_args[0][0], Path("../") / self.outDir / self.hash)
