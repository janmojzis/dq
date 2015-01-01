#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include "env.h"
#include "die.h"
#include "strtonum.h"
#include "e.h"
#include "droproot.h"


static void die_fatal(const char *fatal, const char *trouble, const char *fn) {

    if (errno) {
        if (fn) die_7(111, fatal, trouble, " ", fn, ": ", e_str(errno), "\n");
        die_5(111, fatal, trouble, ": ", e_str(errno), "\n");
    }
    if (fn) die_5(111, fatal, trouble, " ", fn, "\n");
    die_3(111, fatal, trouble, "\n");
}

void droproot(const char *fatal) {

    char *x;
    long long id;
    gid_t gid;
    uid_t uid;

    x = env_get("ROOT");
    if (!x) die_fatal(fatal, "$ROOT not set", 0);

    if (chdir(x) == -1) die_fatal(fatal, "unable to chdir to", x);
    if (chroot(".") == -1) die_fatal(fatal, "unable to chroot to", x);

    x = env_get("GID");
    if (!x) die_fatal(fatal, "$GID not set", 0);
    if (!strtonum(&id, x)) die_fatal(fatal, "unable to parse $GID", 0);
    gid = id;
    if (id != (long long)gid) die_fatal(fatal, "bad $GID", 0);
    if (setgroups(1, &gid) == -1) die_fatal(fatal, "unable to setgid", 0);
    if (setgid(gid) == -1) die_fatal(fatal, "unable to setgid", 0);
    if (getgid() != gid) die_fatal(fatal, "unable to setgid", 0);

    x = env_get("UID");
    if (!x) die_fatal(fatal, "$UID not set", 0);
    if (!strtonum(&id, x)) die_fatal(fatal, "unable to parse $UID", 0);
    uid = id;
    if (id != (long long)uid) die_fatal(fatal, "bad $UID", 0);
    if (setuid(uid) == -1) die_fatal(fatal, "unable to setuid", 0);
    if (getuid() != uid) die_fatal(fatal, "unable to setuid", 0);
}
