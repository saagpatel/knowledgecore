use crate::ingest::{IngestResourceLimits, ScanFolderResourceLimits};
use crate::sync::SyncSnapshotResourceLimits;

pub const MIB: usize = 1024 * 1024;

pub const INGEST_SINGLE_FILE_MAX_BYTES: usize = 100 * MIB;
pub const SCAN_FOLDER_MAX_FILES: usize = 10_000;
pub const SCAN_FOLDER_MAX_DEPTH: usize = 12;
pub const PDF_INPUT_MAX_BYTES: usize = 100 * MIB;
pub const PDF_EXTRACTED_TEXT_MAX_BYTES: usize = 25 * MIB;
pub const OCR_MAX_PAGES: usize = 100;
pub const SYNC_SNAPSHOT_MAX_ARCHIVE_BYTES: usize = 2 * 1024 * MIB;
pub const SYNC_SNAPSHOT_MAX_ENTRIES: usize = 250_000;
pub const SYNC_SNAPSHOT_MAX_ENTRY_BYTES: u64 = (250 * MIB) as u64;
pub const VECTOR_REBUILD_MAX_ROWS: usize = 100_000;
pub const VECTOR_ROW_MAX_TEXT_BYTES: usize = MIB;

pub fn ingest_single_file_limits() -> IngestResourceLimits {
    IngestResourceLimits {
        max_bytes: INGEST_SINGLE_FILE_MAX_BYTES,
    }
}

pub fn scan_folder_limits() -> ScanFolderResourceLimits {
    ScanFolderResourceLimits {
        max_files: SCAN_FOLDER_MAX_FILES,
        max_depth: SCAN_FOLDER_MAX_DEPTH,
        max_bytes_per_file: INGEST_SINGLE_FILE_MAX_BYTES,
    }
}

pub fn sync_snapshot_limits() -> SyncSnapshotResourceLimits {
    SyncSnapshotResourceLimits {
        max_archive_bytes: SYNC_SNAPSHOT_MAX_ARCHIVE_BYTES,
        max_entries: SYNC_SNAPSHOT_MAX_ENTRIES,
        max_entry_bytes: SYNC_SNAPSHOT_MAX_ENTRY_BYTES,
    }
}
