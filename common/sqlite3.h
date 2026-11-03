#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define SQLITE_OK           0   /* Successful result */
#define SQLITE_ERROR        1   /* Generic error */
#define SQLITE_ROW          100  /* sqlite3_step() has another row ready */
#define SQLITE_DONE         101  /* sqlite3_step() has finished executing */

#define SQLITE_STATIC      ((void(*)(void *))0)
#define SQLITE_TRANSIENT   ((void(*)(void *))-1)

#define SQLITE_OPEN_READONLY         0x00000001  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_READWRITE        0x00000002  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_CREATE           0x00000004  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_NOMUTEX          0x00008000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_FULLMUTEX        0x00010000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_SHAREDCACHE      0x00020000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_PRIVATECACHE     0x00040000  /* Ok for sqlite3_open_v2() */
#define SQLITE_OPEN_WAL              0x00080000  /* VFS only */

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef long long int sqlite3_int64;
typedef unsigned long long int sqlite3_uint64;

__declspec(dllimport) int sqlite3_open(const char *filename, sqlite3 **ppDb);
__declspec(dllimport) int sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
__declspec(dllimport) int sqlite3_close(sqlite3*);
__declspec(dllimport) int sqlite3_exec(sqlite3*, const char *sql, int (*callback)(void*,int,char**,char**), void *, char **errmsg);
__declspec(dllimport) void sqlite3_free(void*);
__declspec(dllimport) const char *sqlite3_errmsg(sqlite3*);

__declspec(dllimport) int sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
__declspec(dllimport) int sqlite3_step(sqlite3_stmt*);
__declspec(dllimport) int sqlite3_finalize(sqlite3_stmt *pStmt);
__declspec(dllimport) int sqlite3_reset(sqlite3_stmt *pStmt);

__declspec(dllimport) int sqlite3_bind_blob(sqlite3_stmt*, int, const void*, int n, void(*)(void*));
__declspec(dllimport) int sqlite3_bind_double(sqlite3_stmt*, int, double);
__declspec(dllimport) int sqlite3_bind_int(sqlite3_stmt*, int, int);
__declspec(dllimport) int sqlite3_bind_int64(sqlite3_stmt*, int, sqlite3_int64);
__declspec(dllimport) int sqlite3_bind_null(sqlite3_stmt*, int);
__declspec(dllimport) int sqlite3_bind_text(sqlite3_stmt*,int,const char*,int,void(*)(void*));

__declspec(dllimport) const void *sqlite3_column_blob(sqlite3_stmt*, int iCol);
__declspec(dllimport) double sqlite3_column_double(sqlite3_stmt*, int iCol);
__declspec(dllimport) int sqlite3_column_int(sqlite3_stmt*, int iCol);
__declspec(dllimport) sqlite3_int64 sqlite3_column_int64(sqlite3_stmt*, int iCol);
__declspec(dllimport) const unsigned char *sqlite3_column_text(sqlite3_stmt*, int iCol);
__declspec(dllimport) int sqlite3_column_bytes(sqlite3_stmt*, int iCol);
__declspec(dllimport) int sqlite3_column_count(sqlite3_stmt *pStmt);

__declspec(dllimport) sqlite3_int64 sqlite3_last_insert_rowid(sqlite3*);
__declspec(dllimport) int sqlite3_changes(sqlite3*);

#ifdef __cplusplus
}
#endif
