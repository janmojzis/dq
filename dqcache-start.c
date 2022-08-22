#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
/* 
workaround for *BSD
#include <stdlib.h>
*/
extern int setenv(const char *, const char *, int);
#include "numtostr.h"
#include "strtonum.h"
#include "e.h"
#include "die.h"

static const char *account;
static const char *root;
static struct passwd *pw;
static long long uid, gid;

#define USAGE "dqcache-start: usage: dqcache-start root-directory account child\n"
#define FATAL "dqcache-start: fatal: "

int main(int argc, char **argv) {

    root = *++argv;
    if (!root) die_1(100, USAGE);

    account = *++argv;
    if (!account || !*++argv) die_1(100, USAGE);

    pw = getpwnam(account);
    if (pw) {
        uid = pw->pw_uid;
        gid = pw->pw_gid;
    }
    else {
        if (!strtonum(&uid, account) || uid < 0)
            die_4(111, FATAL, "unknown account ", account, "\n");
        gid = uid;
    }

    if (chdir(root) == -1) die_6(111, FATAL, "unable to change directory to ", root, ": ", e_str(errno), "\n");
    if (chown("dump", uid, gid) == -1) die_6(111, FATAL, "unable to change owner on ", root, "/dump: ", e_str(errno), "\n");

    if (setenv("ROOT", root, 1) == -1)
        die_4(111, FATAL, "unable to set env. variable ROOT: ", e_str(errno), "\n");
    if (setenv("GID", numtostr(0, gid), 1) == -1)
        die_4(111, FATAL, "unable to set env. variable GID: ", e_str(errno), "\n");
    if (setenv("UID", numtostr(0, uid), 1) == -1)
        die_4(111, FATAL, "unable to set env. variable UID: ", e_str(errno), "\n");

    execvp(*argv, argv);
    die_6(111, FATAL, "unable to run ", *argv, ": ", e_str(errno), "\n");
    return 111;
}
