#ifndef _MNBN_H_
#define _MNBN_H_

#define MNBND_UNIX_DOMAIN       "/tmp/mnbnd.socket"

/* structure passing info from target from mnbnd */
struct mnbn_target_req {
        pid_t pid;
};

#endif /* _MNBN_H_ */
