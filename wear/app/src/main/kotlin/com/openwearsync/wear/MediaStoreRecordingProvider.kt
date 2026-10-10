package com.openwearsync.wear

import android.content.ContentResolver
import android.provider.MediaStore
import java.io.InputStream

// START_MODULE_CONTRACT
// PURPOSE: Read Samsung Voice Recorder metadata through unprivileged MediaStore APIs.
// SCOPE: MediaStore query and content URI streams; no ADB, root, or private path assumptions.
// DEPENDS: M-ANDROID-PLATFORM, M-WEAR-SHELL
// LINKS: M-ANDROID-PLATFORM, M-WEAR-SHELL, V-M-ANDROID-PLATFORM, DF-RECORDING-MANIFEST
// END_MODULE_CONTRACT

// START_MODULE_MAP
//   MediaStoreRecordingProvider - Android ContentResolver-backed RecordingProvider.
// END_MODULE_MAP

class MediaStoreRecordingProvider(
    private val resolver: ContentResolver,
    private val isVoiceRecorderPath: (String?) -> Boolean = { path ->
        path == null || path.contains("voice recorder", ignoreCase = true)
    },
) : RecordingProvider {
    private val collection = MediaStore.Audio.Media.EXTERNAL_CONTENT_URI

    override fun listRecords(): List<SourceRecord> {
        val projection = arrayOf(
            MediaStore.Audio.Media._ID,
            MediaStore.Audio.Media.DISPLAY_NAME,
            MediaStore.Audio.Media.MIME_TYPE,
            MediaStore.Audio.Media.SIZE,
            MediaStore.Audio.Media.DATE_MODIFIED,
            MediaStore.Audio.Media.IS_PENDING,
            MediaStore.Audio.Media.RELATIVE_PATH,
        )
        val records = mutableListOf<SourceRecord>()
        resolver.query(collection, projection, null, null, "${MediaStore.Audio.Media.DATE_MODIFIED} DESC")?.use { cursor ->
            val idColumn = cursor.getColumnIndexOrThrow(MediaStore.Audio.Media._ID)
            val nameColumn = cursor.getColumnIndexOrThrow(MediaStore.Audio.Media.DISPLAY_NAME)
            val mimeColumn = cursor.getColumnIndexOrThrow(MediaStore.Audio.Media.MIME_TYPE)
            val sizeColumn = cursor.getColumnIndexOrThrow(MediaStore.Audio.Media.SIZE)
            val modifiedColumn = cursor.getColumnIndexOrThrow(MediaStore.Audio.Media.DATE_MODIFIED)
            val pendingColumn = cursor.getColumnIndexOrThrow(MediaStore.Audio.Media.IS_PENDING)
            val pathColumn = cursor.getColumnIndexOrThrow(MediaStore.Audio.Media.RELATIVE_PATH)
            while (cursor.moveToNext()) {
                val relativePath = cursor.getString(pathColumn)
                if (!isVoiceRecorderPath(relativePath)) continue
                val id = cursor.getLong(idColumn)
                val size = cursor.getLong(sizeColumn).takeIf { it >= 0L }
                val pending = cursor.getInt(pendingColumn)
                records += SourceRecord(
                    uri = collection.buildUpon().appendPath(id.toString()).build().toString(),
                    displayName = cursor.getString(nameColumn) ?: "recording-$id",
                    mimeType = cursor.getString(mimeColumn),
                    sizeBytes = size,
                    stability = when {
                        pending == 1 -> Stability.IN_PROGRESS
                        size == null || size <= 0L -> Stability.UNKNOWN
                        else -> Stability.STABLE
                    },
                    modifiedEpochSeconds = cursor.getLong(modifiedColumn),
                )
            }
        }
        return records
    }

    override fun openStream(uri: String): InputStream = resolver.openInputStream(android.net.Uri.parse(uri))
        ?: throw java.io.FileNotFoundException("MediaStore URI is unavailable: $uri")
}
