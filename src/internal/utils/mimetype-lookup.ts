// MIME type lookup by file extension.

import { extname } from 'path';

const MIME_MAP: Record<string, string> = {
  // Documents - PDF
  '.pdf': 'application/pdf',

  // Documents - Microsoft Office
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',

  // Documents - OpenDocument
  '.odt': 'application/vnd.oasis.opendocument.text',
  '.ods': 'application/vnd.oasis.opendocument.spreadsheet',
  '.odp': 'application/vnd.oasis.opendocument.presentation',

  // Images
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.bmp': 'image/bmp',
  '.tif': 'image/tiff',
  '.tiff': 'image/tiff',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.heic': 'image/heic',               // iPhone photos
  '.heif': 'image/heif',               // High Efficiency Image Format

  // Audio (claims: recorded statements, voicemails, call recordings)
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.m4a': 'audio/mp4',                 // iPhone voice memos
  '.aac': 'audio/aac',
  '.ogg': 'audio/ogg',
  '.wma': 'audio/x-ms-wma',
  '.flac': 'audio/flac',

  // Video (claims: dashcam, bodycam, surveillance, damage documentation)
  '.mp4': 'video/mp4',
  '.mov': 'video/quicktime',           // iPhone videos
  '.avi': 'video/x-msvideo',
  '.wmv': 'video/x-ms-wmv',
  '.mkv': 'video/x-matroska',
  '.webm': 'video/webm',
  '.m4v': 'video/x-m4v',
  '.3gp': 'video/3gpp',                // Older phone videos
  '.ts': 'video/mp2t',                 // MPEG transport stream (dashcam)

  // Text/Data
  '.txt': 'text/plain',
  '.csv': 'text/csv',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.html': 'text/html',
  '.htm': 'text/html',
  '.rtf': 'application/rtf',

  // Archives
  '.zip': 'application/zip',
  '.gz': 'application/gzip',
  '.gzip': 'application/gzip',
  '.tar': 'application/x-tar',
  '.7z': 'application/x-7z-compressed',
  '.rar': 'application/vnd.rar',

  // Email
  '.eml': 'message/rfc822',
  '.msg': 'application/vnd.ms-outlook',

  // Insurance Industry Formats
  '.al3': 'application/x-al3',           // ACORD AL3 (Agency/Company interface)
  '.tt2': 'application/x-turbotag',      // TurboTag indexing files
  '.acord': 'application/xml',           // ACORD XML forms
  '.idx': 'application/x-index',         // Index files (common in document management)

  // EDI/Financial Formats
  '.edi': 'application/EDI-X12',         // EDI X12 transactions
  '.x12': 'application/EDI-X12',         // EDI X12 alternate extension
  '.837': 'application/EDI-X12',         // Healthcare claims
  '.835': 'application/EDI-X12',         // Healthcare remittance
  '.834': 'application/EDI-X12',         // Benefit enrollment
  '.270': 'application/EDI-X12',         // Eligibility inquiry
  '.271': 'application/EDI-X12',         // Eligibility response
  '.820': 'application/EDI-X12',         // Payment order/remittance
  '.850': 'application/EDI-X12',         // Purchase order
  '.856': 'application/EDI-X12',         // Ship notice/manifest
  '.810': 'application/EDI-X12',         // Invoice

  // Financial Data Formats
  '.ofx': 'application/x-ofx',           // Open Financial Exchange
  '.qfx': 'application/x-qfx',           // Quicken Financial Exchange
  '.qbo': 'application/x-qbo',           // QuickBooks Online
  '.qif': 'application/x-qif',           // Quicken Interchange Format
  '.iif': 'text/plain',                  // Intuit Interchange Format

  // Database/Reporting
  '.mdb': 'application/x-msaccess',      // Access database
  '.accdb': 'application/x-msaccess',    // Access 2007+ database
  '.dbf': 'application/x-dbf',           // dBASE database files
};

/**
 * Look up MIME type by file path or extension.
 *
 * @param path - File path or extension (e.g., 'file.pdf', '.pdf', or 'pdf')
 * @returns MIME type string, or false if not found/invalid input
 */
export function lookupMimeType(path: unknown): string | false {
  if (typeof path !== 'string' || path === '') {
    return false;
  }

  let ext = extname(path).toLowerCase();

  // Bare extension without leading dot (e.g., 'html' or 'pdf')
  if (ext === '' && !path.includes('/') && !path.includes('\\')) {
    if (!path.includes('.')) {
      ext = '.' + path.toLowerCase();
    } else if (path.endsWith('.')) {
      return false;
    }
  }

  if (ext === '') {
    return false;
  }

  return MIME_MAP[ext] ?? false;
}
