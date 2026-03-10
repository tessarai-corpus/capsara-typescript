/// <reference types="vitest/globals" />
/**
 * Tests for mimetype-lookup utility
 * @module tests/unit/internal/utils/mimetype-lookup.test
 *
 * Note: On Windows, path.extname('.pdf') returns '' because it's treated as a dotfile,
 * not as an extension. Therefore, tests use 'file.ext' format for MIME type validation
 * and bare extensions like 'pdf' (without leading dot) for bare extension tests.
 */

import { lookupMimeType } from '../../../../src/internal/utils/mimetype-lookup.js';

describe('lookupMimeType', () => {
  describe('Invalid Input Handling', () => {
    describe('Non-string inputs', () => {
      it('should return false for null', () => {
        expect(lookupMimeType(null)).toBe(false);
      });

      it('should return false for undefined', () => {
        expect(lookupMimeType(undefined)).toBe(false);
      });

      it('should return false for numbers', () => {
        expect(lookupMimeType(42)).toBe(false);
        expect(lookupMimeType(0)).toBe(false);
        expect(lookupMimeType(-1)).toBe(false);
        expect(lookupMimeType(3.14)).toBe(false);
        expect(lookupMimeType(NaN)).toBe(false);
        expect(lookupMimeType(Infinity)).toBe(false);
      });

      it('should return false for objects', () => {
        expect(lookupMimeType({})).toBe(false);
        expect(lookupMimeType({ ext: '.pdf' })).toBe(false);
        expect(lookupMimeType([])).toBe(false);
        expect(lookupMimeType(['.pdf'])).toBe(false);
      });

      it('should return false for boolean values', () => {
        expect(lookupMimeType(true)).toBe(false);
        expect(lookupMimeType(false)).toBe(false);
      });

      it('should return false for functions', () => {
        expect(lookupMimeType(() => '.pdf')).toBe(false);
      });

      it('should return false for symbols', () => {
        expect(lookupMimeType(Symbol('.pdf'))).toBe(false);
      });
    });

    describe('Empty and whitespace strings', () => {
      it('should return false for empty string', () => {
        expect(lookupMimeType('')).toBe(false);
      });
    });

    describe('Paths without extension', () => {
      it('should return false for path without extension', () => {
        expect(lookupMimeType('/path/to/json')).toBe(false);
      });

      it('should return false for Windows path without extension', () => {
        expect(lookupMimeType('C:\\Users\\file')).toBe(false);
      });

      it('should return false for relative path without extension', () => {
        expect(lookupMimeType('./folder/document')).toBe(false);
      });
    });

    describe('Dotfiles without extension', () => {
      it('should return false for dotfile without extension in path', () => {
        expect(lookupMimeType('/path/to/.json')).toBe(false);
      });

      it('should return false for dotfile in current directory', () => {
        expect(lookupMimeType('.gitignore')).toBe(false);
      });

      it('should return false for Windows dotfile path', () => {
        expect(lookupMimeType('C:\\Users\\.config')).toBe(false);
      });

      it('should return false for dot-prefixed extension (treated as dotfile)', () => {
        // On Windows, '.pdf' is treated as a dotfile, not as an extension with a leading dot
        // This is because path.extname('.pdf') returns '' on Windows
        expect(lookupMimeType('.pdf')).toBe(false);
        expect(lookupMimeType('.html')).toBe(false);
        expect(lookupMimeType('.json')).toBe(false);
      });
    });

    describe('Trailing dot with no extension', () => {
      it('should return false for filename with trailing dot', () => {
        expect(lookupMimeType('file.')).toBe(false);
      });

      it('should return false for path with trailing dot', () => {
        expect(lookupMimeType('/path/to/file.')).toBe(false);
      });

      it('should return false for single dot', () => {
        // Edge case: single dot is treated as current directory reference
        expect(lookupMimeType('.')).toBe(false);
      });

      it('should return false for double dot', () => {
        // Edge case: double dot is treated as parent directory reference
        expect(lookupMimeType('..')).toBe(false);
      });
    });

    describe('Unknown extensions', () => {
      it('should return false for unknown extension', () => {
        expect(lookupMimeType('file.unknown123')).toBe(false);
      });

      it('should return false for made-up bare extension', () => {
        expect(lookupMimeType('xyz789')).toBe(false);
      });
    });
  });

  describe('Valid Input Formats', () => {
    describe('Extension without leading dot (bare extension)', () => {
      it('should resolve bare extension', () => {
        expect(lookupMimeType('html')).toBe('text/html');
        expect(lookupMimeType('pdf')).toBe('application/pdf');
        expect(lookupMimeType('json')).toBe('application/json');
      });
    });

    describe('Case insensitivity', () => {
      it('should resolve uppercase bare extensions', () => {
        expect(lookupMimeType('HTML')).toBe('text/html');
        expect(lookupMimeType('PDF')).toBe('application/pdf');
        expect(lookupMimeType('JSON')).toBe('application/json');
      });

      it('should resolve mixed case bare extensions', () => {
        expect(lookupMimeType('HtMl')).toBe('text/html');
        expect(lookupMimeType('PdF')).toBe('application/pdf');
        expect(lookupMimeType('JsOn')).toBe('application/json');
      });

      it('should resolve uppercase in file paths', () => {
        expect(lookupMimeType('/path/to/FILE.PDF')).toBe('application/pdf');
        expect(lookupMimeType('C:\\Users\\Document.DOCX')).toBe(
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        );
      });
    });

    describe('Full file paths', () => {
      it('should extract extension from Unix paths', () => {
        expect(lookupMimeType('/path/to/document.pdf')).toBe('application/pdf');
        expect(lookupMimeType('/var/log/data.json')).toBe('application/json');
      });

      it('should extract extension from Windows paths', () => {
        expect(lookupMimeType('C:\\Users\\Documents\\file.docx')).toBe(
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        );
      });

      it('should extract extension from relative paths', () => {
        expect(lookupMimeType('./folder/image.png')).toBe('image/png');
        expect(lookupMimeType('../parent/video.mp4')).toBe('video/mp4');
      });

      it('should handle filenames with multiple dots', () => {
        expect(lookupMimeType('file.backup.2024.pdf')).toBe('application/pdf');
        expect(lookupMimeType('archive.tar.gz')).toBe('application/gzip');
      });
    });
  });

  describe('MIME Type Categories', () => {
    describe('PDF Documents', () => {
      it('should resolve PDF extension', () => {
        expect(lookupMimeType('pdf')).toBe('application/pdf');
        expect(lookupMimeType('document.pdf')).toBe('application/pdf');
      });
    });

    describe('Microsoft Office Documents', () => {
      it('should resolve Word documents', () => {
        expect(lookupMimeType('doc')).toBe('application/msword');
        expect(lookupMimeType('file.doc')).toBe('application/msword');
        expect(lookupMimeType('docx')).toBe(
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        );
        expect(lookupMimeType('file.docx')).toBe(
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        );
      });

      it('should resolve Excel spreadsheets', () => {
        expect(lookupMimeType('xls')).toBe('application/vnd.ms-excel');
        expect(lookupMimeType('file.xls')).toBe('application/vnd.ms-excel');
        expect(lookupMimeType('xlsx')).toBe(
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        );
        expect(lookupMimeType('file.xlsx')).toBe(
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        );
      });

      it('should resolve PowerPoint presentations', () => {
        expect(lookupMimeType('ppt')).toBe('application/vnd.ms-powerpoint');
        expect(lookupMimeType('file.ppt')).toBe('application/vnd.ms-powerpoint');
        expect(lookupMimeType('pptx')).toBe(
          'application/vnd.openxmlformats-officedocument.presentationml.presentation'
        );
        expect(lookupMimeType('file.pptx')).toBe(
          'application/vnd.openxmlformats-officedocument.presentationml.presentation'
        );
      });
    });

    describe('OpenDocument Formats', () => {
      it('should resolve OpenDocument text', () => {
        expect(lookupMimeType('odt')).toBe('application/vnd.oasis.opendocument.text');
        expect(lookupMimeType('file.odt')).toBe('application/vnd.oasis.opendocument.text');
      });

      it('should resolve OpenDocument spreadsheet', () => {
        expect(lookupMimeType('ods')).toBe('application/vnd.oasis.opendocument.spreadsheet');
        expect(lookupMimeType('file.ods')).toBe('application/vnd.oasis.opendocument.spreadsheet');
      });

      it('should resolve OpenDocument presentation', () => {
        expect(lookupMimeType('odp')).toBe('application/vnd.oasis.opendocument.presentation');
        expect(lookupMimeType('file.odp')).toBe('application/vnd.oasis.opendocument.presentation');
      });
    });

    describe('Images', () => {
      it('should resolve JPEG images', () => {
        expect(lookupMimeType('jpg')).toBe('image/jpeg');
        expect(lookupMimeType('file.jpg')).toBe('image/jpeg');
        expect(lookupMimeType('jpeg')).toBe('image/jpeg');
        expect(lookupMimeType('file.jpeg')).toBe('image/jpeg');
      });

      it('should resolve PNG images', () => {
        expect(lookupMimeType('png')).toBe('image/png');
        expect(lookupMimeType('file.png')).toBe('image/png');
      });

      it('should resolve GIF images', () => {
        expect(lookupMimeType('gif')).toBe('image/gif');
        expect(lookupMimeType('file.gif')).toBe('image/gif');
      });

      it('should resolve BMP images', () => {
        expect(lookupMimeType('bmp')).toBe('image/bmp');
        expect(lookupMimeType('file.bmp')).toBe('image/bmp');
      });

      it('should resolve TIFF images', () => {
        expect(lookupMimeType('tif')).toBe('image/tiff');
        expect(lookupMimeType('file.tif')).toBe('image/tiff');
        expect(lookupMimeType('tiff')).toBe('image/tiff');
        expect(lookupMimeType('file.tiff')).toBe('image/tiff');
      });

      it('should resolve WebP images', () => {
        expect(lookupMimeType('webp')).toBe('image/webp');
        expect(lookupMimeType('file.webp')).toBe('image/webp');
      });

      it('should resolve SVG images', () => {
        expect(lookupMimeType('svg')).toBe('image/svg+xml');
        expect(lookupMimeType('file.svg')).toBe('image/svg+xml');
      });

      it('should resolve HEIC/HEIF images (iPhone)', () => {
        expect(lookupMimeType('heic')).toBe('image/heic');
        expect(lookupMimeType('file.heic')).toBe('image/heic');
        expect(lookupMimeType('heif')).toBe('image/heif');
        expect(lookupMimeType('file.heif')).toBe('image/heif');
      });
    });

    describe('Audio Files', () => {
      it('should resolve MP3 audio', () => {
        expect(lookupMimeType('mp3')).toBe('audio/mpeg');
        expect(lookupMimeType('file.mp3')).toBe('audio/mpeg');
      });

      it('should resolve WAV audio', () => {
        expect(lookupMimeType('wav')).toBe('audio/wav');
        expect(lookupMimeType('file.wav')).toBe('audio/wav');
      });

      it('should resolve M4A audio (iPhone voice memos)', () => {
        expect(lookupMimeType('m4a')).toBe('audio/mp4');
        expect(lookupMimeType('file.m4a')).toBe('audio/mp4');
      });

      it('should resolve AAC audio', () => {
        expect(lookupMimeType('aac')).toBe('audio/aac');
        expect(lookupMimeType('file.aac')).toBe('audio/aac');
      });

      it('should resolve OGG audio', () => {
        expect(lookupMimeType('ogg')).toBe('audio/ogg');
        expect(lookupMimeType('file.ogg')).toBe('audio/ogg');
      });

      it('should resolve WMA audio', () => {
        expect(lookupMimeType('wma')).toBe('audio/x-ms-wma');
        expect(lookupMimeType('file.wma')).toBe('audio/x-ms-wma');
      });

      it('should resolve FLAC audio', () => {
        expect(lookupMimeType('flac')).toBe('audio/flac');
        expect(lookupMimeType('file.flac')).toBe('audio/flac');
      });
    });

    describe('Video Files', () => {
      it('should resolve MP4 video', () => {
        expect(lookupMimeType('mp4')).toBe('video/mp4');
        expect(lookupMimeType('file.mp4')).toBe('video/mp4');
      });

      it('should resolve MOV video (iPhone)', () => {
        expect(lookupMimeType('mov')).toBe('video/quicktime');
        expect(lookupMimeType('file.mov')).toBe('video/quicktime');
      });

      it('should resolve AVI video', () => {
        expect(lookupMimeType('avi')).toBe('video/x-msvideo');
        expect(lookupMimeType('file.avi')).toBe('video/x-msvideo');
      });

      it('should resolve WMV video', () => {
        expect(lookupMimeType('wmv')).toBe('video/x-ms-wmv');
        expect(lookupMimeType('file.wmv')).toBe('video/x-ms-wmv');
      });

      it('should resolve MKV video', () => {
        expect(lookupMimeType('mkv')).toBe('video/x-matroska');
        expect(lookupMimeType('file.mkv')).toBe('video/x-matroska');
      });

      it('should resolve WebM video', () => {
        expect(lookupMimeType('webm')).toBe('video/webm');
        expect(lookupMimeType('file.webm')).toBe('video/webm');
      });

      it('should resolve M4V video', () => {
        expect(lookupMimeType('m4v')).toBe('video/x-m4v');
        expect(lookupMimeType('file.m4v')).toBe('video/x-m4v');
      });

      it('should resolve 3GP video (older phones)', () => {
        expect(lookupMimeType('3gp')).toBe('video/3gpp');
        expect(lookupMimeType('file.3gp')).toBe('video/3gpp');
      });

      it('should resolve TS video (dashcam)', () => {
        expect(lookupMimeType('ts')).toBe('video/mp2t');
        expect(lookupMimeType('file.ts')).toBe('video/mp2t');
      });
    });

    describe('Text and Data Files', () => {
      it('should resolve plain text', () => {
        expect(lookupMimeType('txt')).toBe('text/plain');
        expect(lookupMimeType('file.txt')).toBe('text/plain');
      });

      it('should resolve CSV', () => {
        expect(lookupMimeType('csv')).toBe('text/csv');
        expect(lookupMimeType('file.csv')).toBe('text/csv');
      });

      it('should resolve JSON', () => {
        expect(lookupMimeType('json')).toBe('application/json');
        expect(lookupMimeType('file.json')).toBe('application/json');
      });

      it('should resolve XML', () => {
        expect(lookupMimeType('xml')).toBe('application/xml');
        expect(lookupMimeType('file.xml')).toBe('application/xml');
      });

      it('should resolve HTML', () => {
        expect(lookupMimeType('html')).toBe('text/html');
        expect(lookupMimeType('file.html')).toBe('text/html');
        expect(lookupMimeType('htm')).toBe('text/html');
        expect(lookupMimeType('file.htm')).toBe('text/html');
      });

      it('should resolve RTF', () => {
        expect(lookupMimeType('rtf')).toBe('application/rtf');
        expect(lookupMimeType('file.rtf')).toBe('application/rtf');
      });
    });

    describe('Archive Files', () => {
      it('should resolve ZIP archives', () => {
        expect(lookupMimeType('zip')).toBe('application/zip');
        expect(lookupMimeType('file.zip')).toBe('application/zip');
      });

      it('should resolve GZIP archives', () => {
        expect(lookupMimeType('gz')).toBe('application/gzip');
        expect(lookupMimeType('file.gz')).toBe('application/gzip');
        expect(lookupMimeType('gzip')).toBe('application/gzip');
        expect(lookupMimeType('file.gzip')).toBe('application/gzip');
      });

      it('should resolve TAR archives', () => {
        expect(lookupMimeType('tar')).toBe('application/x-tar');
        expect(lookupMimeType('file.tar')).toBe('application/x-tar');
      });

      it('should resolve 7Z archives', () => {
        expect(lookupMimeType('7z')).toBe('application/x-7z-compressed');
        expect(lookupMimeType('file.7z')).toBe('application/x-7z-compressed');
      });

      it('should resolve RAR archives', () => {
        expect(lookupMimeType('rar')).toBe('application/vnd.rar');
        expect(lookupMimeType('file.rar')).toBe('application/vnd.rar');
      });
    });

    describe('Email Files', () => {
      it('should resolve EML files', () => {
        expect(lookupMimeType('eml')).toBe('message/rfc822');
        expect(lookupMimeType('file.eml')).toBe('message/rfc822');
      });

      it('should resolve MSG files (Outlook)', () => {
        expect(lookupMimeType('msg')).toBe('application/vnd.ms-outlook');
        expect(lookupMimeType('file.msg')).toBe('application/vnd.ms-outlook');
      });
    });

    describe('Insurance Industry Formats', () => {
      it('should resolve AL3 files (ACORD)', () => {
        expect(lookupMimeType('al3')).toBe('application/x-al3');
        expect(lookupMimeType('file.al3')).toBe('application/x-al3');
      });

      it('should resolve TT2 files (TurboTag)', () => {
        expect(lookupMimeType('tt2')).toBe('application/x-turbotag');
        expect(lookupMimeType('file.tt2')).toBe('application/x-turbotag');
      });

      it('should resolve ACORD XML files', () => {
        expect(lookupMimeType('acord')).toBe('application/xml');
        expect(lookupMimeType('file.acord')).toBe('application/xml');
      });

      it('should resolve IDX index files', () => {
        expect(lookupMimeType('idx')).toBe('application/x-index');
        expect(lookupMimeType('file.idx')).toBe('application/x-index');
      });
    });

    describe('EDI Formats', () => {
      it('should resolve generic EDI files', () => {
        expect(lookupMimeType('edi')).toBe('application/EDI-X12');
        expect(lookupMimeType('file.edi')).toBe('application/EDI-X12');
        expect(lookupMimeType('x12')).toBe('application/EDI-X12');
        expect(lookupMimeType('file.x12')).toBe('application/EDI-X12');
      });

      it('should resolve healthcare EDI files', () => {
        expect(lookupMimeType('837')).toBe('application/EDI-X12');
        expect(lookupMimeType('file.837')).toBe('application/EDI-X12');
        expect(lookupMimeType('835')).toBe('application/EDI-X12');
        expect(lookupMimeType('file.835')).toBe('application/EDI-X12');
        expect(lookupMimeType('834')).toBe('application/EDI-X12');
        expect(lookupMimeType('file.834')).toBe('application/EDI-X12');
        expect(lookupMimeType('270')).toBe('application/EDI-X12');
        expect(lookupMimeType('file.270')).toBe('application/EDI-X12');
        expect(lookupMimeType('271')).toBe('application/EDI-X12');
        expect(lookupMimeType('file.271')).toBe('application/EDI-X12');
      });

      it('should resolve business EDI files', () => {
        expect(lookupMimeType('820')).toBe('application/EDI-X12');
        expect(lookupMimeType('file.820')).toBe('application/EDI-X12');
        expect(lookupMimeType('850')).toBe('application/EDI-X12');
        expect(lookupMimeType('file.850')).toBe('application/EDI-X12');
        expect(lookupMimeType('856')).toBe('application/EDI-X12');
        expect(lookupMimeType('file.856')).toBe('application/EDI-X12');
        expect(lookupMimeType('810')).toBe('application/EDI-X12');
        expect(lookupMimeType('file.810')).toBe('application/EDI-X12');
      });
    });

    describe('Financial Data Formats', () => {
      it('should resolve OFX files', () => {
        expect(lookupMimeType('ofx')).toBe('application/x-ofx');
        expect(lookupMimeType('file.ofx')).toBe('application/x-ofx');
      });

      it('should resolve QFX files (Quicken)', () => {
        expect(lookupMimeType('qfx')).toBe('application/x-qfx');
        expect(lookupMimeType('file.qfx')).toBe('application/x-qfx');
      });

      it('should resolve QBO files (QuickBooks Online)', () => {
        expect(lookupMimeType('qbo')).toBe('application/x-qbo');
        expect(lookupMimeType('file.qbo')).toBe('application/x-qbo');
      });

      it('should resolve QIF files (Quicken Interchange)', () => {
        expect(lookupMimeType('qif')).toBe('application/x-qif');
        expect(lookupMimeType('file.qif')).toBe('application/x-qif');
      });

      it('should resolve IIF files (Intuit Interchange)', () => {
        expect(lookupMimeType('iif')).toBe('text/plain');
        expect(lookupMimeType('file.iif')).toBe('text/plain');
      });
    });

    describe('Database Formats', () => {
      it('should resolve MDB files (Access)', () => {
        expect(lookupMimeType('mdb')).toBe('application/x-msaccess');
        expect(lookupMimeType('file.mdb')).toBe('application/x-msaccess');
      });

      it('should resolve ACCDB files (Access 2007+)', () => {
        expect(lookupMimeType('accdb')).toBe('application/x-msaccess');
        expect(lookupMimeType('file.accdb')).toBe('application/x-msaccess');
      });

      it('should resolve DBF files (dBASE)', () => {
        expect(lookupMimeType('dbf')).toBe('application/x-dbf');
        expect(lookupMimeType('file.dbf')).toBe('application/x-dbf');
      });
    });
  });

  describe('Real-World File Path Scenarios', () => {
    it('should handle typical document paths', () => {
      expect(lookupMimeType('/home/user/Documents/claim-form.pdf')).toBe('application/pdf');
      expect(lookupMimeType('C:\\Claims\\2024\\damage-photos.zip')).toBe('application/zip');
    });

    it('should handle paths with spaces (when passed as string)', () => {
      expect(lookupMimeType('/path/to/my document.pdf')).toBe('application/pdf');
      expect(lookupMimeType('C:\\My Documents\\report.xlsx')).toBe(
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      );
    });

    it('should handle paths with special characters', () => {
      expect(lookupMimeType('/path/to/file-with-dashes.pdf')).toBe('application/pdf');
      expect(lookupMimeType('/path/to/file_with_underscores.pdf')).toBe('application/pdf');
      expect(lookupMimeType('/path/to/file(1).pdf')).toBe('application/pdf');
    });

    it('should handle network paths', () => {
      expect(lookupMimeType('\\\\server\\share\\document.docx')).toBe(
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      );
    });

    it('should handle dotfiles with extensions in paths', () => {
      // Dotfiles WITH an extension should resolve
      expect(lookupMimeType('/path/to/.config.json')).toBe('application/json');
      expect(lookupMimeType('/path/to/.backup.pdf')).toBe('application/pdf');
    });
  });
});
