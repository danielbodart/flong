/* flong-sweeper: the holder unit's process.
 *
 *   flong-sweeper STATE-DIR
 *
 * Runs in the holder unit's DelegateSubgroup=supervisor leaf, so the unit's
 * cgroup, which every session lives under, stays up while no session does.
 * It sweeps sessions/ at start and again each time a record is closed, so a
 * SIGKILLed launcher's postStop and hook daemons go within milliseconds of
 * its death, not at the next launch. It runs until it is killed, and exits
 * 125 when it cannot start or cannot go on.
 */
#include <signal.h>

#include "flong-cgroup.h"
#include "flong-record.h"
#include "flong-util.h"

int main(int argc, char **argv)
{
	struct fl_holder h;
	int state_fd, sessions_fd;

	fl_prog = "flong-sweeper";
	/* stderr is the journal's pipe: if it goes, a message is lost, not the
	 * sweeper. */
	signal(SIGPIPE, SIG_IGN);
	/* An ignored SIGCHLD survives execve, and fl_poststop's waitid needs
	 * the status the kernel would then discard. */
	signal(SIGCHLD, SIG_DFL);
	if (argc != 2) {
		fl_errx("usage: flong-sweeper STATE-DIR");
		return 125;
	}
	if (fl_refuse_root() < 0)
		return 125;
	if (state_open(argv[1], &state_fd, &sessions_fd) < 0)
		return 125;
	if (cg_holder_self(&h) < 0)
		return 125;
	rec_watch(sessions_fd, &h);
	return 125;
}
