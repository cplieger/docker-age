# How docker-age works

This page explains what a decrypt pass does, how each plaintext file is written, and what the waiting container does between deploys. It is for readers who want to know why a pass fails or how it behaves next to other passes.

## Encrypted and plain files stay apart

Each secret lives in git as `<name>.enc`, and docker-age writes the plaintext to `<name>` beside it, so `apps/x/.env.enc` becomes `apps/x/.env`. The `.enc` file is opened read-only and never changed. The plain file is generated and belongs in `.gitignore`.

Your compose files keep reading `apps/x/.env` as usual. `git status` stays meaningful on the server, and `git pull` never conflicts with a decrypted secret. When you rotate a secret, `git pull` brings the new `.enc` file and the next pass writes the new plaintext. A plain file that git still tracks is overwritten all the same, and the checkout then shows it as changed. Remove such files from git with `git rm --cached`.

## A decrypt pass

A pass searches the folder you name, or `REPO_ROOT`, and handles each file it finds:

- It reads the first bytes of each `.enc` file. `-----BEGIN AGE ENCRYPTED FILE-----` marks the armored age format and `age-encryption.org/v1` the binary one. Anything else fails the pass, because a `.enc` file that holds no age payload means the encrypt step went wrong.
- It decrypts with every identity in the identity file, so a file encrypted to any one of them decrypts.
- It refuses two names before decrypting anything. A file named only `.enc` has no plain name. A file named `<x>.enc.enc` would write a file that looks encrypted again and fails the next pass.
- With `--ext`, it checks each plain file the filter matches. Encrypted text there fails the pass with `stray age ciphertext at a plaintext path`, naming the file. This catches a secret encrypted in place instead of saved as `<name>.enc`. When a regular `<name>.enc` file sits beside it, that file's own result decides instead. A successful decrypt replaces the stale text, and a failed one leaves it in place and fails the pass.

A pass that searches its folders ends with one summary line, `decryption complete` or `decryption failed`, carrying four counts. `decrypted` counts the files written and `failed` the files that failed. `skipped` counts the plain files `--ext` checked and left alone, and `walk_errors` the folders that could not be read. Any failure or unreadable folder makes the command exit 1, so the deploy stops. When it cannot reach a path you named or `REPO_ROOT`, it logs `target not accessible`, `cannot open repo root` or `repo root unreadable` and exits 1 with no summary line. A pass that finds nothing exits 0 and logs `no matching files found`.

Running a pass again gives the same result. Each pass reads the unchanged `.enc` files and writes the same plaintext.

## Writing a plain file

docker-age writes each plaintext to a new file in the same folder, with a random name ending `.age-decrypt-tmp` and mode 0600. It then checks that file and renames it over `<name>`. An app reading `<name>` sees the old contents or the new ones, never half a file. A failed write leaves `<name>` as it was, then empties and removes the temporary file. When that cleanup fails, the pass logs `temp cleanup error` with the file's name.

File names ending `.age-decrypt-tmp` are reserved for these files. A stopped pass can leave one behind. A later pass tries to remove those it recognizes as its own once they are 10 minutes old, empties one it cannot remove, and logs the reason when neither works. Keep your own files out of that name pattern.

Several passes can run on the same checkout at once, as when two stacks deploy together. Each uses its own random temporary names. The cleanup leaves files younger than 10 minutes alone, so it does not touch a file another pass is writing.

## The waiting container

Without a command, the container starts, marks itself healthy and waits. It does no decrypting of its own. Each `docker exec age /age-decrypt decrypt ...` starts a separate process that does one pass and exits with its result.

The waiting process needs `IDENTITY_PATH` set but never reads the identity file. A bad key therefore fails each `decrypt` command loudly while the container stays up, ready for the next try. A container that exited on a bad key would restart in a loop and leave nothing for the deploy step to reach.

The healthcheck runs `/age-decrypt health` every 30 seconds, with a 5-second timeout, 3 retries and a 15-second start period. It reads `/tmp/.healthy`, which the waiting process writes when it starts and removes when it stops. The healthcheck says only whether that process is alive. A decrypt result never changes it.

## Stopping a pass

A stop signal, `SIGINT` or `SIGTERM`, during a pass makes the command exit 1, and it never reports success. A plain file is written completely or not at all. The last check for a stop comes just before the rename. A signal that arrives after that check can still let that one file be written before the command exits 1. For `decrypt -`, the same holds for the write to standard output.
