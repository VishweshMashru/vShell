#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_TOKENS 256
#define MAX_ARGS   128

/* -------------------- utils -------------------- */

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) die("malloc failed\n");
    return p;
}

static char *xstrdup(const char *s) {
    char *d = strdup(s ? s : "");
    if (!d) die("strdup failed\n");
    return d;
}

/* -------------------- signal handling -------------------- */

static volatile sig_atomic_t got_sigchld = 0;

static void sigint_handler(int sig) {
    (void)sig;
    write(STDOUT_FILENO, "\n", 1);
}

static void sigchld_handler(int sig) {
    (void)sig;
    got_sigchld = 1;
}

/* reap any finished background children */
static void reap_children(void) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (WIFEXITED(status)) {
            dprintf(STDERR_FILENO, "[bg] pid %d exited with %d\n", pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            dprintf(STDERR_FILENO, "[bg] pid %d killed by signal %d\n", pid, WTERMSIG(status));
        }
    }
    got_sigchld = 0;
}

/* -------------------- lexer -------------------- */
/* Tokens: words (with quotes), |, <, >, >>, &, EOL */

typedef enum {
    T_WORD, T_PIPE, T_LT, T_GT, T_GTGT, T_AMP, T_EOL
} TokType;

typedef struct {
    TokType type;
    char   *text;  // for T_WORD
} Token;

typedef struct {
    Token items[MAX_TOKENS];
    size_t n;
} TokenList;

/* append token */
static void add_tok(TokenList *tl, TokType t, const char *txt) {
    if (tl->n >= MAX_TOKENS) die("too many tokens\n");
    tl->items[tl->n].type = t;
    tl->items[tl->n].text = (t == T_WORD) ? xstrdup(txt) : NULL;
    tl->n++;
}

/* simple $VAR expansion inside a single token (no braces), and ~ at start */
static char *expand_var_and_tilde(const char *in) {
    /* tilde expansion */
    const char *home = getenv("HOME");
    size_t outcap = strlen(in) + (home ? strlen(home) : 0) + 64;
    char *out = xmalloc(outcap);
    size_t oi = 0;

    size_t i = 0;
    if (in[0] == '~' && (in[1] == '/' || in[1] == '\0')) {
        if (home) {
            size_t hl = strlen(home);
            memcpy(out + oi, home, hl); oi += hl;
            i = 1;
        }
    }

    for (; in[i]; ++i) {
        if (in[i] == '$') {
            /* parse var name [A-Za-z_][A-Za-z0-9_]* */
            size_t j = i + 1;
            if (!( (in[j]>='A'&&in[j]<='Z') || (in[j]>='a'&&in[j]<='z') || in[j]=='_')) {
                out[oi++] = in[i]; /* literal $ */
                continue;
            }
            size_t start = j;
            while ((in[j]>='A'&&in[j]<='Z') || (in[j]>='a'&&in[j]<='z') || (in[j]>='0'&&in[j]<='9') || in[j]=='_') j++;
            char var[256];
            size_t len = j - start;
            if (len >= sizeof var) len = sizeof var - 1;
            memcpy(var, in + start, len); var[len] = '\0';
            const char *val = getenv(var);
            if (val) {
                size_t vl = strlen(val);
                if (oi + vl + 2 > outcap) { outcap = (oi + vl + 2) * 2; out = realloc(out, outcap); }
                memcpy(out + oi, val, vl); oi += vl;
            }
            i = j - 1; /* advance */
        } else {
            if (oi + 2 > outcap) { outcap *= 2; out = realloc(out, outcap); }
            out[oi++] = in[i];
        }
    }
    out[oi] = '\0';
    return out;
}

/* tokenize with support for quotes and special symbols */
static void lex_line(const char *line, TokenList *tl) {
    tl->n = 0;
    size_t i = 0, n = strlen(line);
    while (i < n) {
        while (i < n && (line[i] == ' ' || line[i] == '\t')) i++;
        if (i >= n) break;

        if (line[i] == '\n') { i++; break; }

        /* operators */
        if (line[i] == '|') { add_tok(tl, T_PIPE, NULL); i++; continue; }
        if (line[i] == '&') { add_tok(tl, T_AMP,  NULL); i++; continue; }
        if (line[i] == '<') { add_tok(tl, T_LT,   NULL); i++; continue; }
        if (line[i] == '>') {
            if (i + 1 < n && line[i+1] == '>') { add_tok(tl, T_GTGT, NULL); i += 2; }
            else { add_tok(tl, T_GT, NULL); i++; }
            continue;
        }

        /* word (supports "..." and '...') */
        char buf[4096]; size_t bi = 0;
        while (i < n && line[i] != ' ' && line[i] != '\t' && line[i] != '\n'
               && line[i] != '|' && line[i] != '&' && line[i] != '<' && line[i] != '>') {

            if (line[i] == '\'' || line[i] == '"') {
                char q = line[i++];
                while (i < n && line[i] != q) {
                    if (bi + 2 >= sizeof buf) die("token too long\n");
                    buf[bi++] = line[i++];
                }
                if (i >= n || line[i] != q) { fprintf(stderr, "unclosed quote\n"); break; }
                i++; /* skip closing quote */
            } else {
                if (bi + 2 >= sizeof buf) die("token too long\n");
                buf[bi++] = line[i++];
            }
        }
        buf[bi] = '\0';
        char *expanded = expand_var_and_tilde(buf);
        add_tok(tl, T_WORD, expanded);
        free(expanded);
    }
    add_tok(tl, T_EOL, NULL);
}

/* -------------------- parser AST -------------------- */

typedef struct Cmd {
    char *argv[MAX_ARGS];
    char *in_redir;      // "< file"
    char *out_redir;     // "> file" or ">> file"
    bool  out_append;    // true if >>
    struct Cmd *next;    // pipeline next
} Cmd;

typedef struct {
    Cmd *first;
    bool background;
} Pipeline;

static Cmd *new_cmd(void) {
    Cmd *c = calloc(1, sizeof *c);
    if (!c) die("calloc\n");
    return c;
}

static void free_cmds(Cmd *c) {
    while (c) {
        Cmd *n = c->next;
        // argv, in_redir, out_redir point to token memory; nothing to free here
        free(c);
        c = n;
    }
}

/* Very simple grammar:
    pipeline := command { '|' command } [ '&' ]
    command  := WORD { WORD } [ redirs... ]
    redir    := '<' WORD | '>' WORD | '>>' WORD
*/
static bool parse_pipeline(const TokenList *tl, size_t *pos, Pipeline *pl) {
    pl->first = NULL; pl->background = false;
    Cmd *head = NULL, *tail = NULL;

    while (1) {
        // command
        Cmd *cmd = new_cmd();
        size_t argc = 0;

        // at least one WORD expected (unless it's empty line)
        if (tl->items[*pos].type != T_WORD) {
            free_cmds(cmd);
            return false;
        }
        while (tl->items[*pos].type == T_WORD && argc + 1 < MAX_ARGS) {
            cmd->argv[argc++] = tl->items[*pos].text;
            (*pos)++;
        }
        cmd->argv[argc] = NULL;

        // zero or more redirs
        while (1) {
            TokType t = tl->items[*pos].type;
            if (t == T_LT || t == T_GT || t == T_GTGT) {
                (*pos)++;
                if (tl->items[*pos].type != T_WORD) {
                    fprintf(stderr, "syntax: redirection needs a filename\n");
                    free_cmds(cmd);
                    return false;
                }
                if (t == T_LT) cmd->in_redir = tl->items[*pos].text;
                else {
                    cmd->out_redir = tl->items[*pos].text;
                    cmd->out_append = (t == T_GTGT);
                }
                (*pos)++;
            } else break;
        }

        if (!head) head = tail = cmd;
        else { tail->next = cmd; tail = cmd; }

        if (tl->items[*pos].type == T_PIPE) { (*pos)++; continue; }
        break;
    }

    if (tl->items[*pos].type == T_AMP) { pl->background = true; (*pos)++; }
    if (tl->items[*pos].type != T_EOL) {
        fprintf(stderr, "syntax error near extra input\n");
        free_cmds(head);
        return false;
    }

    pl->first = head;
    return true;
}

/* -------------------- execution -------------------- */

static int run_command(Cmd *cmd, bool is_bg) {
    /* built-ins handled only if single command in pipeline and foreground (except bg still ok) */
    if (cmd && !cmd->next) {
        if (cmd->argv[0] && strcmp(cmd->argv[0], "cd") == 0) {
            const char *target = cmd->argv[1];
            if (!target) target = getenv("HOME");
            if (!target) { fprintf(stderr, "cd: HOME not set\n"); return 1; }
            if (chdir(target) != 0) perror("cd");
            return 0;
        } else if (cmd->argv[0] && strcmp(cmd->argv[0], "pwd") == 0) {
            char buf[4096];
            if (getcwd(buf, sizeof buf)) printf("%s\n", buf);
            else perror("pwd");
            return 0;
        } else if (cmd->argv[0] && strcmp(cmd->argv[0], "exit") == 0) {
            exit(0);
        }
    }

    int status = 0;
    int in_fd = -1, out_fd = -1;

    int prev_read = -1;
    for (Cmd *c = cmd; c; c = c->next) {
        int pipefd[2] = {-1,-1};
        if (c->next && pipe(pipefd) < 0) { perror("pipe"); return 1; }

        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid == 0) {
            /* child: restore default SIGINT */
            signal(SIGINT, SIG_DFL);
            signal(SIGCHLD, SIG_DFL);

            /* input: previous pipe or < file */
            if (prev_read != -1) {
                dup2(prev_read, STDIN_FILENO);
            }
            if (c->in_redir) {
                in_fd = open(c->in_redir, O_RDONLY);
                if (in_fd < 0) { perror("open <"); _exit(1); }
                dup2(in_fd, STDIN_FILENO);
            }

            /* output: next pipe or > / >> file */
            if (c->next) {
                dup2(pipefd[1], STDOUT_FILENO);
            }
            if (c->out_redir) {
                int flags = O_CREAT | O_WRONLY | (c->out_append ? O_APPEND : O_TRUNC);
                out_fd = open(c->out_redir, flags, 0644);
                if (out_fd < 0) { perror("open >"); _exit(1); }
                dup2(out_fd, STDOUT_FILENO);
            }

            /* close fds in child */
            if (pipefd[0] != -1) close(pipefd[0]);
            if (pipefd[1] != -1) close(pipefd[1]);
            if (prev_read != -1) close(prev_read);
            if (in_fd != -1) close(in_fd);
            if (out_fd != -1) close(out_fd);

            execvp(c->argv[0], c->argv);
            perror("execvp");
            _exit(127);
        } else {
            /* parent */
            if (c->next) {
                if (prev_read != -1) close(prev_read);
                prev_read = pipefd[0];
                close(pipefd[1]);
            } else {
                if (prev_read != -1) close(prev_read);
            }

            if (!is_bg) {
                int wstatus;
                /* wait for the *last* stage when foreground; still collect all to avoid zombies */
                if (!c->next) {
                    while (waitpid(pid, &wstatus, 0) < 0 && errno == EINTR) {}
                    status = (WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : 128 + WTERMSIG(wstatus));
                }
            } else {
                fprintf(stderr, "[bg] started pid %d\n", pid);
            }
        }
    }
    return status;
}

/* -------------------- main loop -------------------- */

static void print_prompt(void) {
    char cwd[4096];
    if (getcwd(cwd, sizeof cwd)) {
        printf("mshell:%s$ ", cwd);
    } else {
        printf("mshell$ ");
    }
    fflush(stdout);
}

int main(void) {
    /* install signal handlers */
    struct sigaction sa_int = {0}, sa_chld = {0};
    sa_int.sa_handler = sigint_handler;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = SA_RESTART;

    sa_chld.sa_handler = sigchld_handler;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART | SA_NOCLDSTOP;

    sigaction(SIGINT, &sa_int, NULL);
    sigaction(SIGCHLD, &sa_chld, NULL);

    char *line = NULL;
    size_t cap = 0;

    for (;;) {
        if (got_sigchld) reap_children();
        print_prompt();

        ssize_t n = getline(&line, &cap, stdin);
        if (n < 0) {
            if (feof(stdin)) { printf("\n"); break; }
            if (errno == EINTR) continue;
            perror("getline"); break;
        }

        TokenList tl; lex_line(line, &tl);

        /* skip empty line */
        if (tl.n == 1 && tl.items[0].type == T_EOL) continue;

        size_t pos = 0;
        Pipeline pl;
        if (!parse_pipeline(&tl, &pos, &pl)) {
            continue;
        }

        /* run */
        run_command(pl.first, pl.background);

        /* free transient AST */
        free_cmds(pl.first);

        /* free token texts */
        for (size_t i = 0; i < tl.n; ++i) {
            if (tl.items[i].type == T_WORD) free(tl.items[i].text);
        }
    }

    free(line);
    return 0;
}
