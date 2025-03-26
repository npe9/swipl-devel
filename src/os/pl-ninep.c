/* File: ninep_stream.c */

#include "SWI-Stream.h"
#include <SWI-Prolog.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Define constants for 9P protocol */
#define MAX_MSG_SIZE 8192
#define VERSION "9P2000"
#define IOUNIT 8192

/* Define 9P message types */
#define Tversion 100
#define Rversion 101
#define Tauth    102
#define Rauth    103
#define Tattach  104
#define Rattach  105
#define Tflush   106
#define Rflush   107
#define Twalk    110
#define Rwalk    111
#define Topen    112
#define Ropen    113
#define Tcreate  114
#define Rcreate  115
#define Tread    116
#define Rread    117
#define Twrite   118
#define Rwrite   119
#define Tclunk   120
#define Rclunk   121
#define Tremove  122
#define Rremove  123
#define Tstat    124
#define Rstat    125
#define Twstat   126
#define Rwstat   127

/* Define a structure to hold the 9P stream state */
typedef struct {
    IOSTREAM *underlying_stream;  /* The underlying stream (e.g., socket or file) */
    uint32_t fid;                 /* File identifier in the 9P protocol */
    uint64_t offset;              /* Current offset in the file */
    uint32_t msize;               /* Maximum message size */
    char version[32];             /* Protocol version */
    uint32_t tag;                 /* Current tag for message matching */
} ninep_stream_state;

/* Function prototypes */
static ssize_t ninep_read(void *handle, char *buf, size_t size);
static ssize_t ninep_write(void *handle, char *buf, size_t size);
static int ninep_close(void *handle);
static long ninep_seek(void *handle, long offset, int whence);
static int send_tversion(ninep_stream_state *state);
static int receive_rversion(ninep_stream_state *state);
static int send_tattach(ninep_stream_state *state, const char *uname, const char *aname);
static int receive_rattach(ninep_stream_state *state);
static int send_twalk(ninep_stream_state *state, uint32_t newfid, const char *path);
static int receive_rwalk(ninep_stream_state *state);
static int send_topen(ninep_stream_state *state, uint8_t mode);
static int receive_ropen(ninep_stream_state *state);
static int send_tread(ninep_stream_state *state, uint64_t offset, uint32_t count);
static int receive_rread(ninep_stream_state *state, char *buf, size_t *bytes_read);
static int send_twrite(ninep_stream_state *state, uint64_t offset, const char *buf, uint32_t count);
static int receive_rwrite(ninep_stream_state *state, uint32_t *bytes_written);

/* Helper functions */
static int send_message(ninep_stream_state *state, const char *msg, size_t len);
static int receive_message(ninep_stream_state *state, char *msg, size_t *len);
static uint32_t next_tag(ninep_stream_state *state);
static void pack_uint8(char **buf, uint8_t val);
static void pack_uint16(char **buf, uint16_t val);
static void pack_uint32(char **buf, uint32_t val);
static void pack_uint64(char **buf, uint64_t val);
static void pack_string(char **buf, const char *str);
static uint8_t unpack_uint8(const char **buf);
static uint16_t unpack_uint16(const char **buf);
static uint32_t unpack_uint32(const char **buf);
static uint64_t unpack_uint64(const char **buf);
static char *unpack_string(const char **buf, uint16_t *len);

/* Implement the custom read function */
static ssize_t ninep_read(void *handle, char *buf, size_t size) {
    ninep_stream_state *state = (ninep_stream_state *)handle;

    /* Send Tread message */
    if (!send_tread(state, state->offset, (uint32_t)size)) {
        return -1;
    }

    /* Receive Rread message */
    size_t bytes_read = 0;
    if (!receive_rread(state, buf, &bytes_read)) {
        return -1;
    }

    /* Update the offset */
    state->offset += bytes_read;

    return bytes_read; /* Return the number of bytes read */
}

/* Implement the custom write function */
static ssize_t ninep_write(void *handle, char *buf, size_t size) {
    ninep_stream_state *state = (ninep_stream_state *)handle;

    /* Send Twrite message */
    if (!send_twrite(state, state->offset, buf, (uint32_t)size)) {
        return -1;
    }

    /* Receive Rwrite message */
    uint32_t bytes_written = 0;
    if (!receive_rwrite(state, &bytes_written)) {
        return -1;
    }

    /* Update the offset */
    state->offset += bytes_written;

    return bytes_written; /* Return the number of bytes written */
}

/* Implement the custom close function */
static int ninep_close(void *handle) {
    ninep_stream_state *state = (ninep_stream_state *)handle;

    /* Implement Tclunk message to release the fid */
    /* For simplicity, we skip error handling here */
    /* TODO: Send Tclunk and receive Rclunk */

    /* Close the underlying stream if needed */
    Sclose(state->underlying_stream);

    /* Free the state */
    free(state);

    return 0; /* Return 0 on success */
}

/* Implement the custom seek function */
static long ninep_seek(void *handle, long offset, int whence) {
    ninep_stream_state *state = (ninep_stream_state *)handle;

    uint64_t new_offset;

    switch (whence) {
        case SIO_SEEK_SET:
            new_offset = offset;
            break;
        case SIO_SEEK_CUR:
            new_offset = state->offset + offset;
            break;
        case SIO_SEEK_END:
            /* For simplicity, we cannot seek relative to EOF without knowing file size */
            /* TODO: Implement getting file size via Tstat */
            return -1; /* Not implemented */
        default:
            return -1; /* Invalid 'whence' value */
    }

    /* Update the offset */
    state->offset = new_offset;

    return new_offset; /* Return the new offset */
}

/* Function to open a 9P stream */
foreign_t pl_ninep_stream_open(term_t UnderlyingStreamTerm, term_t FilePathTerm, term_t NinePStreamTerm) {
    IOSTREAM *underlying_stream;
    char *file_path;

    /* Get the underlying stream from the Prolog term */
    if (!PL_get_stream(UnderlyingStreamTerm, &underlying_stream, SIO_INPUT | SIO_OUTPUT)) {
        PL_fail;
    }

    /* Get the file path from the Prolog term */
    if (!PL_get_chars(FilePathTerm, &file_path, CVT_ATOM | CVT_STRING | CVT_EXCEPTION)) {
        PL_release_stream(underlying_stream);
        PL_fail;
    }

    /* Allocate and initialize the stream state */
    ninep_stream_state *state = malloc(sizeof(ninep_stream_state));
    if (state == NULL) {
        PL_release_stream(underlying_stream);
        PL_fail;
    }

    state->underlying_stream = underlying_stream;
    state->fid = 1; /* Assign a file identifier; for simplicity, use 1 */
    state->offset = 0;
    state->msize = MAX_MSG_SIZE;
    strncpy(state->version, VERSION, sizeof(state->version));
    state->tag = 0;

    /* Perform 9P handshake */
    if (!send_tversion(state) || !receive_rversion(state)) {
        free(state);
        PL_release_stream(underlying_stream);
        PL_fail;
    }

    /* Perform Tattach */
    if (!send_tattach(state, "nobody", "")) {
        free(state);
        PL_release_stream(underlying_stream);
        PL_fail;
    }
    if (!receive_rattach(state)) {
        free(state);
        PL_release_stream(underlying_stream);
        PL_fail;
    }

    /* Perform Twalk to the file */
    if (!send_twalk(state, state->fid, file_path)) {
        free(state);
        PL_release_stream(underlying_stream);
        PL_fail;
    }
    if (!receive_rwalk(state)) {
        free(state);
        PL_release_stream(underlying_stream);
        PL_fail;
    }

    /* Perform Topen */
    if (!send_topen(state, 0)) { /* 0 for OREAD */
        free(state);
        PL_release_stream(underlying_stream);
        PL_fail;
    }
    if (!receive_ropen(state)) {
        free(state);
        PL_release_stream(underlying_stream);
        PL_fail;
    }

    /* Create the custom stream */
    IOSTREAM *ninep_stream = Snew(state, (SIO_INPUT | SIO_OUTPUT), &(IOFUNCTIONS){
        .read = ninep_read,
        .write = ninep_write,
        .seek = ninep_seek,
        .close = ninep_close,
        /* Add other function pointers as needed */
    });

    if (ninep_stream == NULL) {
        free(state);
        PL_release_stream(underlying_stream);
        PL_fail;
    }

    /* Set stream properties */
    ninep_stream->encoding = ENC_OCTET; /* Use binary encoding */
    ninep_stream->flags |= SIO_FBUF; /* Use full buffering */

    /* Return the new stream to Prolog */
    if (!PL_unify_stream(NinePStreamTerm, ninep_stream)) {
        Sclose(ninep_stream);
        PL_fail;
    }

    PL_succeed;
}

/* Implement the send and receive functions for 9P messages */

static int send_tversion(ninep_stream_state *state) {
    char buffer[MAX_MSG_SIZE];
    char *p = buffer;

    /* Message size placeholder */
    uint32_t msg_size = 0;
    pack_uint32(&p, msg_size); /* Will be filled later */

    /* Type and tag */
    pack_uint8(&p, Tversion);
    uint16_t tag = next_tag(state);
    pack_uint16(&p, tag);

    /* Msize */
    pack_uint32(&p, state->msize);

    /* Version string */
    pack_string(&p, state->version);

    /* Calculate message size */
    msg_size = (uint32_t)(p - buffer);
    memcpy(buffer, &msg_size, 4); /* Update message size */

    /* Send the message */
    return send_message(state, buffer, msg_size);
}

static int receive_rversion(ninep_stream_state *state) {
    char buffer[MAX_MSG_SIZE];
    size_t msg_len = MAX_MSG_SIZE;

    /* Receive the message */
    if (!receive_message(state, buffer, &msg_len)) {
        return 0;
    }

    const char *p = buffer;

    /* Unpack message size */
    uint32_t msg_size = unpack_uint32(&p);
    if (msg_size != msg_len) {
        return 0;
    }

    /* Unpack type and tag */
    uint8_t type = unpack_uint8(&p);
    uint16_t tag = unpack_uint16(&p);

    if (type != Rversion) {
        return 0;
    }

    /* Unpack msize and version */
    uint32_t msize = unpack_uint32(&p);
    uint16_t version_len;
    char *version = unpack_string(&p, &version_len);

    /* Update state */
    state->msize = msize;
    strncpy(state->version, version, sizeof(state->version) - 1);

    free(version);

    return 1;
}

static int send_tattach(ninep_stream_state *state, const char *uname, const char *aname) {
    char buffer[MAX_MSG_SIZE];
    char *p = buffer;

    /* Message size placeholder */
    uint32_t msg_size = 0;
    pack_uint32(&p, msg_size); /* Will be filled later */

    /* Type and tag */
    pack_uint8(&p, Tattach);
    uint16_t tag = next_tag(state);
    pack_uint16(&p, tag);

    /* Fid and afid */
    pack_uint32(&p, state->fid); /* fid */
    pack_uint32(&p, (uint32_t)-1); /* afid: no authentication */

    /* uname and aname */
    pack_string(&p, uname);
    pack_string(&p, aname);

    /* Calculate message size */
    msg_size = (uint32_t)(p - buffer);
    memcpy(buffer, &msg_size, 4); /* Update message size */

    /* Send the message */
    return send_message(state, buffer, msg_size);
}

static int receive_rattach(ninep_stream_state *state) {
    char buffer[MAX_MSG_SIZE];
    size_t msg_len = MAX_MSG_SIZE;

    /* Receive the message */
    if (!receive_message(state, buffer, &msg_len)) {
        return 0;
    }

    const char *p = buffer;

    /* Unpack message size */
    uint32_t msg_size = unpack_uint32(&p);
    if (msg_size != msg_len) {
        return 0;
    }

    /* Unpack type and tag */
    uint8_t type = unpack_uint8(&p);
    uint16_t tag = unpack_uint16(&p);

    if (type != Rattach) {
        return 0;
    }

    /* Unpack Qid (we ignore it here) */
    p += 13; /* Skip Qid (13 bytes) */

    return 1;
}

static int send_twalk(ninep_stream_state *state, uint32_t newfid, const char *path) {
    char buffer[MAX_MSG_SIZE];
    char *p = buffer;

    /* Split the path into components */
    char *path_copy = strdup(path);
    if (path_copy == NULL) {
        return 0;
    }

    char *token;
    char *rest = path_copy;
    int name_count = 0;
    char *names[16]; /* Adjust as needed */

    while ((token = strtok_r(rest, "/", &rest)) && name_count < 16) {
        names[name_count++] = token;
    }

    /* Message size placeholder */
    uint32_t msg_size = 0;
    pack_uint32(&p, msg_size); /* Will be filled later */

    /* Type and tag */
    pack_uint8(&p, Twalk);
    uint16_t tag = next_tag(state);
    pack_uint16(&p, tag);

    /* Fid and newfid */
    pack_uint32(&p, state->fid);
    pack_uint32(&p, newfid);

    /* Number of names */
    pack_uint16(&p, (uint16_t)name_count);

    /* Names */
    for (int i = 0; i < name_count; i++) {
        pack_string(&p, names[i]);
    }

    /* Calculate message size */
    msg_size = (uint32_t)(p - buffer);
    memcpy(buffer, &msg_size, 4); /* Update message size */

    free(path_copy);

    /* Send the message */
    return send_message(state, buffer, msg_size);
}

static int receive_rwalk(ninep_stream_state *state) {
    char buffer[MAX_MSG_SIZE];
    size_t msg_len = MAX_MSG_SIZE;

    /* Receive the message */
    if (!receive_message(state, buffer, &msg_len)) {
        return 0;
    }

    const char *p = buffer;

    /* Unpack message size */
    uint32_t msg_size = unpack_uint32(&p);
    if (msg_size != msg_len) {
        return 0;
    }

    /* Unpack type and tag */
    uint8_t type = unpack_uint8(&p);
    uint16_t tag = unpack_uint16(&p);

    if (type != Rwalk) {
        return 0;
    }

    /* Unpack number of Qids */
    uint16_t nwqid = unpack_uint16(&p);

    /* Skip Qids */
    p += nwqid * 13; /* Each Qid is 13 bytes */

    return 1;
}

static int send_topen(ninep_stream_state *state, uint8_t mode) {
    char buffer[MAX_MSG_SIZE];
    char *p = buffer;

    /* Message size placeholder */
    uint32_t msg_size = 0;
    pack_uint32(&p, msg_size); /* Will be filled later */

    /* Type and tag */
    pack_uint8(&p, Topen);
    uint16_t tag = next_tag(state);
    pack_uint16(&p, tag);

    /* Fid and mode */
    pack_uint32(&p, state->fid);
    pack_uint8(&p, mode);

    /* Calculate message size */
    msg_size = (uint32_t)(p - buffer);
    memcpy(buffer, &msg_size, 4); /* Update message size */

    /* Send the message */
    return send_message(state, buffer, msg_size);
}

static int receive_ropen(ninep_stream_state *state) {
    char buffer[MAX_MSG_SIZE];
    size_t msg_len = MAX_MSG_SIZE;

    /* Receive the message */
    if (!receive_message(state, buffer, &msg_len)) {
        return 0;
    }

    const char *p = buffer;

    /* Unpack message size */
    uint32_t msg_size = unpack_uint32(&p);
    if (msg_size != msg_len) {
        return 0;
    }

    /* Unpack type and tag */
    uint8_t type = unpack_uint8(&p);
    uint16_t tag = unpack_uint16(&p);

    if (type != Ropen) {
        return 0;
    }

    /* Unpack Qid (we ignore it here) */
    p += 13; /* Skip Qid (13 bytes) */

    /* Unpack iounit */
    uint32_t iounit = unpack_uint32(&p);

    /* Update msize if iounit is non-zero and less than msize */
    if (iounit > 0 && iounit < state->msize) {
        state->msize = iounit;
    }

    return 1;
}

static int send_tread(ninep_stream_state *state, uint64_t offset, uint32_t count) {
    char buffer[MAX_MSG_SIZE];
    char *p = buffer;

    if (count > state->msize - 24) {
        count = state->msize - 24; /* Adjust count based on msize */
    }

    /* Message size placeholder */
    uint32_t msg_size = 0;
    pack_uint32(&p, msg_size); /* Will be filled later */

    /* Type and tag */
    pack_uint8(&p, Tread);
    uint16_t tag = next_tag(state);
    pack_uint16(&p, tag);

    /* Fid, offset, count */
    pack_uint32(&p, state->fid);
    pack_uint64(&p, offset);
    pack_uint32(&p, count);

    /* Calculate message size */
    msg_size = (uint32_t)(p - buffer);
    memcpy(buffer, &msg_size, 4); /* Update message size */

    /* Send the message */
    return send_message(state, buffer, msg_size);
}

static int receive_rread(ninep_stream_state *state, char *buf, size_t *bytes_read) {
    char buffer[MAX_MSG_SIZE];
    size_t msg_len = MAX_MSG_SIZE;

    /* Receive the message */
    if (!receive_message(state, buffer, &msg_len)) {
        return 0;
    }

    const char *p = buffer;

    /* Unpack message size */
    uint32_t msg_size = unpack_uint32(&p);
    if (msg_size != msg_len) {
        return 0;
    }

    /* Unpack type and tag */
    uint8_t type = unpack_uint8(&p);
    uint16_t tag = unpack_uint16(&p);

    if (type != Rread) {
        return 0;
    }

    /* Unpack data length */
    uint32_t data_len = unpack_uint32(&p);

    /* Copy data to buffer */
    if (data_len > msg_len - (p - buffer)) {
        return 0; /* Data length exceeds message length */
    }

    memcpy(buf, p, data_len);
    *bytes_read = data_len;

    return 1;
}

static int send_twrite(ninep_stream_state *state, uint64_t offset, const char *buf, uint32_t count) {
    char buffer[MAX_MSG_SIZE];
    char *p = buffer;

    if (count > state->msize - 24) {
        count = state->msize - 24; /* Adjust count based on msize */
    }

    /* Message size placeholder */
    uint32_t msg_size = 0;
    pack_uint32(&p, msg_size); /* Will be filled later */

    /* Type and tag */
    pack_uint8(&p, Twrite);
    uint16_t tag = next_tag(state);
    pack_uint16(&p, tag);

    /* Fid, offset, count */
    pack_uint32(&p, state->fid);
    pack_uint64(&p, offset);
    pack_uint32(&p, count);

    /* Data */
    memcpy(p, buf, count);
    p += count;

    /* Calculate message size */
    msg_size = (uint32_t)(p - buffer);
    memcpy(buffer, &msg_size, 4); /* Update message size */

    /* Send the message */
    return send_message(state, buffer, msg_size);
}

static int receive_rwrite(ninep_stream_state *state, uint32_t *bytes_written) {
    char buffer[MAX_MSG_SIZE];
    size_t msg_len = MAX_MSG_SIZE;

    /* Receive the message */
    if (!receive_message(state, buffer, &msg_len)) {
        return 0;
    }

    const char *p = buffer;

    /* Unpack message size */
    uint32_t msg_size = unpack_uint32(&p);
    if (msg_size != msg_len) {
        return 0;
    }

    /* Unpack type and tag */
    uint8_t type = unpack_uint8(&p);
    uint16_t tag = unpack_uint16(&p);

    if (type != Rwrite) {
        return 0;
    }

    /* Unpack count */
    *bytes_written = unpack_uint32(&p);

    return 1;
}

/* Helper functions for sending and receiving messages */

static int send_message(ninep_stream_state *state, const char *msg, size_t len) {
    size_t bytes_written = Sfwrite(msg, 1, len, state->underlying_stream);
    if (bytes_written != len) {
        return 0;
    }
    Sflush(state->underlying_stream);
    return 1;
}

static int receive_message(ninep_stream_state *state, char *msg, size_t *len) {
    /* Read the first 4 bytes to get the message size */
    size_t bytes_read = Sfread(msg, 1, 4, state->underlying_stream);
    if (bytes_read != 4) {
        return 0;
    }

    const char *p = msg;
    uint32_t msg_size = unpack_uint32(&p);
    if (msg_size > *len) {
        return 0; /* Message too big */
    }

    /* Read the rest of the message */
    bytes_read = Sfread(msg + 4, 1, msg_size - 4, state->underlying_stream);
    if (bytes_read != msg_size - 4) {
        return 0;
    }

    *len = msg_size;
    return 1;
}

static uint32_t next_tag(ninep_stream_state *state) {
    state->tag++;
    if (state->tag == (uint16_t)-1) {
        state->tag = 1; /* Skip tag -1 */
    }
    return state->tag;
}

/* Packing functions */

static void pack_uint8(char **buf, uint8_t val) {
    **buf = val;
    (*buf)++;
}

static void pack_uint16(char **buf, uint16_t val) {
    (*buf)[0] = val & 0xFF;
    (*buf)[1] = (val >> 8) & 0xFF;
    (*buf) += 2;
}

static void pack_uint32(char **buf, uint32_t val) {
    (*buf)[0] = val & 0xFF;
    (*buf)[1] = (val >> 8) & 0xFF;
    (*buf)[2] = (val >> 16) & 0xFF;
    (*buf)[3] = (val >> 24) & 0xFF;
    (*buf) += 4;
}

static void pack_uint64(char **buf, uint64_t val) {
    pack_uint32(buf, val & 0xFFFFFFFF);
    pack_uint32(buf, (val >> 32) & 0xFFFFFFFF);
}

static void pack_string(char **buf, const char *str) {
    uint16_t len = (uint16_t)strlen(str);
    pack_uint16(buf, len);
    memcpy(*buf, str, len);
    (*buf) += len;
}

/* Unpacking functions */

static uint8_t unpack_uint8(const char **buf) {
    uint8_t val = **buf;
    (*buf)++;
    return val;
}

static uint16_t unpack_uint16(const char **buf) {
    uint16_t val = (*buf)[0] | ((*buf)[1] << 8);
    (*buf) += 2;
    return val;
}

static uint32_t unpack_uint32(const char **buf) {
    uint32_t val = (*buf)[0] | ((*buf)[1] << 8) | ((*buf)[2] << 16) | ((*buf)[3] << 24);
    (*buf) += 4;
    return val;
}

static uint64_t unpack_uint64(const char **buf) {
    uint64_t val = unpack_uint32(buf);
    val |= ((uint64_t)unpack_uint32(buf)) << 32;
    return val;
}

static char *unpack_string(const char **buf, uint16_t *len) {
    *len = unpack_uint16(buf);
    char *str = malloc(*len + 1);
    memcpy(str, *buf, *len);
    str[*len] = '\0';
    (*buf) += *len;
    return str;
}

/* Install the predicate */
install_t install_ninep_stream() {
    PL_register_foreign("ninep_stream_open", 3, pl_ninep_stream_open, 0);
}

