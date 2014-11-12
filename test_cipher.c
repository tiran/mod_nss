/* Copyright 2001-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sslproto.h>

/* Fake a few Apache and NSPR data types and definitions */
typedef char server_rec;
typedef int PRBool;
typedef int PRInt32;

#define PR_FALSE 0
#define PR_TRUE 1

#include <nss_engine_cipher.h>

extern cipher_properties ciphers_def[];

/* An Apache-like error logger */
int ap_log_error_(const char *fn, int line, int module_index,
                 int level, int status,
                 const server_rec *s, char *fmt, ...)
{
    char out[1024];
    va_list args;

    va_start(args, fmt);
    vsprintf(out, fmt, args);
    fprintf(stderr,"%s:%d, %s", fn, line, out);
    va_end(args);

    return 0;
}

#define ap_log_error_ ap_log_error

int main(int argc, char ** argv)
{
    int rv=0;
    int i;
    char *ciphers;
    PRBool ciphers_list[ciphernum];

    if (argc != 2) {
        fprintf(stderr, "Usage: test_cipher [--count] <cipher_list>\n");
        exit(1);
    }

    if (!strcmp(argv[1], "--count")) {
        fprintf(stdout, "%d\n", ciphernum);
        exit(0);
    }

    for (i=0; i<ciphernum; i++)
    {
        ciphers_list[i] = PR_FALSE;
    }

    ciphers = strdup(argv[1]);
    if (nss_parse_ciphers(NULL, ciphers, ciphers_list) < 0) {
        fprintf(stderr, "Unable to parse cipher list\n");
        rv = 1;
    }
    free(ciphers);

    /* Done parsing, print the results, if any */
    if (rv == 0)
    {
        char output[1024 * 10];

        for (i = 0; i < ciphernum; i++)
        {
            if (ciphers_list[i] == 1) {
                strncat(output,  ciphers_def[i].name, sizeof(output));
                strncat(output,  ", ", sizeof(output));
            }
        }
        output[strlen(output) - 2] = '\0';
        fprintf(stdout, "%s\n", output);
    }

    return rv;
}
