/*  Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2024, SWI-Prolog Solutions b.v.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in
       the documentation and/or other materials provided with the
       distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
    FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
    ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef PL_9P_H_INCLUDED
#define PL_9P_H_INCLUDED

#include "SWI-Prolog.h"
#include "../pl-stream.h"

/* 9P error codes */
#define E9P_NONE          0
#define E9P_IO           -1    /* I/O error */
#define E9P_PROTOCOL     -2    /* Protocol error */
#define E9P_AUTH         -3    /* Authentication error */
#define E9P_PERMISSION   -4    /* Permission denied */
#define E9P_NOTFOUND     -5    /* File not found */
#define E9P_EXISTS       -6    /* File exists */
#define E9P_INVALID      -7    /* Invalid argument */
#define E9P_NOMEM        -8    /* Out of memory */
#define E9P_MSGSIZE      -9    /* Message too large */
#define E9P_TIMEOUT      -10   /* Operation timed out */
#define E9P_CONNECTION   -11   /* Connection error */

/* 9P QID types */
#define QTFILE     0x00
#define QTEXCL     0x11
#define QTMOUNT    0x12
#define QTAPPEND   0x14
#define QTAUTH     0x02
#define QTDIR      0x80
#define QTSYMLINK  0x40
#define QTLINK     0x20
#define QTTMP      0x04
#define QTPIPE     0x08

/* 9P QID structure */
typedef struct _9p_qid {
    uint8_t type;
    uint32_t version;
    uint64_t path;
} _9p_qid;

/* 9P STAT structure */
typedef struct _9p_stat_data {
    uint16_t size;
    uint16_t type;
    uint32_t dev;
    _9p_qid qid;
    uint32_t mode;
    uint32_t atime;
    uint32_t mtime;
    uint32_t length;
    char name[256];
    char uid[32];
    char gid[32];
    char muid[32];
} _9p_stat_data;

/* 9P error structure */
typedef struct _9p_error {
    int code;           /* Error code */
    char message[256];  /* Error message */
    int error_no;      /* System errno if applicable */
} _9p_error;

/* 9P message types */
#define Tversion    100
#define Rversion    101
#define Tauth       102
#define Rauth       103
#define Tattach     104
#define Rattach     105
#define Terror      106
#define Rerror      107
#define Tflush      108
#define Rflush      109
#define Twalk       110
#define Rwalk       111
#define Topen       112
#define Ropen       113
#define Tcreate     114
#define Rcreate     115
#define Tread       116
#define Rread       117
#define Twrite      118
#define Rwrite      119
#define Tclunk      120
#define Rclunk      121
#define Tremove     122
#define Rremove     123
#define Tstat       124
#define Rstat       125
#define Twstat      126
#define Rwstat      127

/* 9P file modes */
#define DMDIR        0x80000000
#define DMAPPEND     0x40000000
#define DMEXCL       0x20000000
#define DMMOUNT      0x10000000
#define DMREAD       0x4
#define DMWRITE      0x2
#define DMEXEC       0x1

/* 9P client structure */
typedef struct _9p_client {
    IOSTREAM *stream;           /* Underlying stream */
    uint32_t msize;            /* Maximum message size */
    uint32_t tag;              /* Current tag */
    char *uname;               /* User name */
    char *aname;               /* Service name */
    uint32_t fid;              /* Current fid */
    uint32_t rootfid;          /* Root fid */
    uint32_t qid;              /* Current qid */
    uint32_t iounit;           /* I/O unit size */
    _9p_error error;          /* Last error */
    uint64_t offset;           /* Current file offset */
} _9p_client;

/* 9P response structures */
typedef struct _9p_attach_resp {
    uint32_t qid;
} _9p_attach_resp;

typedef struct _9p_walk_resp {
    uint16_t nwqid;
    _9p_qid *wqids;
} _9p_walk_resp;

typedef struct _9p_open_resp {
    _9p_qid qid;
    uint32_t iounit;
} _9p_open_resp;

typedef struct _9p_read_resp {
    uint32_t count;
    uint8_t *data;
} _9p_read_resp;

typedef struct _9p_write_resp {
    uint32_t count;
} _9p_write_resp;

typedef struct _9p_stat_resp {
    _9p_stat_data stat;
} _9p_stat_resp;

/* Function declarations */
int _9p_init_client(_9p_client *client, IOSTREAM *stream);
int _9p_version(_9p_client *client, uint32_t msize);
int _9p_attach(_9p_client *client, const char *uname, const char *aname);
int _9p_walk(_9p_client *client, uint32_t fid, uint32_t newfid, const char **wnames, int nwname);
int _9p_open(_9p_client *client, uint32_t fid, uint8_t mode);
int _9p_read(_9p_client *client, uint32_t fid, uint64_t offset, uint32_t count);
int _9p_write(_9p_client *client, uint32_t fid, uint64_t offset, const void *data, uint32_t count);
int _9p_clunk(_9p_client *client, uint32_t fid);
int _9p_remove(_9p_client *client, uint32_t fid);
int _9p_stat(_9p_client *client, uint32_t fid);
int _9p_wstat(_9p_client *client, uint32_t fid, const void *stat);
void _9p_cleanup_client(_9p_client *client);

/* Error handling functions */
void _9p_set_error(_9p_client *client, int code, const char *message);
const char* _9p_error_string(_9p_client *client);
int _9p_error_code(_9p_client *client);
void _9p_clear_error(_9p_client *client);

/* Stream callbacks */
static ssize_t _9p_read_stream(void *handle, char *buf, size_t size);
static ssize_t _9p_write_stream(void *handle, char *buf, size_t size);
static int _9p_close_stream(void *handle);
static int _9p_control_stream(void *handle, int action, void *arg);

#endif /* PL_9P_H_INCLUDED */ 