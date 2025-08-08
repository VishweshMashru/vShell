# VShell — Minimal Unix Shell in C

`vShell` is a small, educational Unix-like shell implemented in pure C (POSIX).  
It supports common shell features like pipelines, I/O redirection, background jobs, and simple variable expansion.

This project is intended as a learning resource for understanding how shells work under the hood, including tokenization, parsing, and process management.

## Features

- Prompt with current working directory
- Built-in commands:
  - `cd [dir]` changes directory (`cd` with no arguments goes to `$HOME`)
  - `pwd` prints the current directory
  - `exit` quits the shell
- Pipelines: `ls | grep .c | wc -l`
- Redirection:
  - Output: `>` (overwrite), `>>` (append)
  - Input: `<`
- Background jobs: `sleep 10 &` (non-blocking)
- Signal handling:
  - Ignores Ctrl+C in the shell but passes it to foreground jobs
  - Reaps background jobs so no zombies remain
- Simple expansions:
  - `~` becomes `$HOME`
  - `$VAR` becomes the value of an environment variable
- Quoted strings for arguments

## Build

```bash
gcc -Wall -Wextra -O2 mshell.c -o vshell
