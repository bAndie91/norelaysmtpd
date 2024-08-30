#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>

#include "config.h"
#include "version.h"

#define BUFSIZE 256
#define DEF_TIMEOUT 300
#define DEF_OLD 30
#define DELAY 5
#define MAXTRY 3
#define SAFECHARS "@0123456789+-._abcdefghijklmnopqrstuvwxyz"

#define EQ(a, b) (strcmp(a, b)==0)

#define SPF_CODE_NEUTRAL 1
#define SPF_CODE_PASS 2
#define SPF_CODE_FAIL 3
#define SPF_CODE_SOFTFAIL 4
#define SPF_CODE_NONE 5
#define SPF_CODE_ERROR_TEMP 6
#define SPF_CODE_ERROR_PERM 7
#define SPF_CODE_ERROR_OTHER 0

const char *EOM = "\r\n.\r\n";

typedef enum {
	DATA,
	EHLO,
	EXPN,
	HELP,
	HELO,
	MAIL,
	NOOP,
	QUIT,
	RCPT,
	RSET,
	VRFY,
	XCLIENT,
	__UNKNOWN__,
	} smtp_verbs;


static char *smtp_commands[] = {
	"DATA",
	"EHLO",
	"EXPN",
	"HELP",
	"HELO",
	"MAIL FROM:",
	"NOOP",
	"QUIT",
	"RCPT TO:",
	"RSET",
	"VRFY",
	"XCLIENT",
	NULL};

typedef struct _to {
	char *email;
	char *rcpt_to;
	char *mboxname;
	FILE *mailbox;
	uid_t uid;
	gid_t gid;
	bool good;
	struct _to *next;
    } recipient;

static char * configfile = SYSCONFDIR"/"SYSCONFBASENAME;
static uid_t uid = (uid_t)(-1);
static gid_t gid = (gid_t)(-1);
static uid_t suid = (uid_t)(-1);
static gid_t sgid = (gid_t)(-1);
static char hostname[BUFSIZE] = "localhost";
static char mailname[BUFSIZE];
static char * mailboxes = DATADIR;
#ifdef SQLITE
static char * dbpath = "/var/cache/norelaysmtpd/db";
static sqlite3 * db = NULL;
static unsigned int greylist_timeout = DEF_TIMEOUT;
static unsigned int greylist_old = DEF_OLD;
#endif
static struct sockaddr_in remote_end;
static char id[BUFSIZE];
static char * helo = NULL;
static char * mail = NULL;
static char * domain = NULL;
static size_t size = 0;
static recipient * recipients = NULL;
static bool esmtp = false;
static unsigned int valid_recipients = 0;
static unsigned int invalid_recipients = 0;
static unsigned int deferred_recipients = 0;
static unsigned int timeout = DEF_TIMEOUT;
static unsigned int badness = 0;
static bool accept_bounces = false;
static bool spf_fail_as_permanent_error = true;

char *peer;
char myip[16];
char myport[6];
char spf_header[BUFSIZE+1];

#ifdef SQLITE
bool open_db()
{
  if(sqlite3_open(dbpath, &db) != SQLITE_OK)
  {
    syslog(LOG_WARNING, "could not access database %s: %s", dbpath, sqlite3_errmsg(db));
    db = NULL;
    return false;
  }

  /* create basic DB structure */
  if(sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS META(key TEXT NOT NULL PRIMARY KEY, value TEXT) ; INSERT OR IGNORE INTO META (key,value) VALUES ('schema', 1) ; CREATE TABLE IF NOT EXISTS clients(ip TEXT NOT NULL, domain TEXT NOT NULL, recipient TEXT NOT NULL, firstseen TEXT DEFAULT CURRENT_TIMESTAMP, lastseen TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE (ip,domain,recipient))", NULL, NULL, NULL) != SQLITE_OK)
  {	/* report error but ignore it */
    syslog(LOG_WARNING, "could not initialise database %s: %s", dbpath, sqlite3_errmsg(db));
  }

  return true;
}

void close_db()
{
  if(!db)
    return;

  sqlite3_close(db);
  db = NULL;
}

bool update_db(const char *recipient)
{
  char *sql = NULL;

  if(!db || !domain|| !recipient)
    return false;

  /* add new client triplet or update 'lastseen' for existing one */
  sql = sqlite3_mprintf("INSERT OR IGNORE INTO clients (ip,domain,recipient) VALUES ('%q', '%q', '%q') ; UPDATE OR IGNORE clients SET lastseen=CURRENT_TIMESTAMP WHERE ip='%q' AND domain='%q' AND recipient='%q'", peer, domain, recipient, peer, domain, recipient);
  if(sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK)
  {	/* report error but ignore it */
    syslog(LOG_WARNING, "could not update database %s: %s", dbpath, sqlite3_errmsg(db));
  }
  sqlite3_free(sql);

  return true;
}

bool badclient_db()
{
  char *sql = NULL;

  if(!db)
    return false;

  sql = sqlite3_mprintf("DELETE FROM clients WHERE ip='%q'", peer);
  if(sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK)
  {	/* report error but ignore it */
    syslog(LOG_WARNING, "could not update database %s: %s", dbpath, sqlite3_errmsg(db));
  }
  sqlite3_free(sql);

  return true;
}

void clean_db()
{
  char *sql = NULL;
  if(!db)
    return;

  /* remove all greylisted entries which are too old to be still considered valid */
  sql = sqlite3_mprintf("DELETE FROM clients WHERE (JULIANDAY('NOW')-JULIANDAY(lastseen)>%d)", greylist_old);
  if(sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK)
    syslog(LOG_WARNING, "database cleanup failed %s: %s", dbpath, sqlite3_errmsg(db));
  sqlite3_free(sql);
  /* remove all greylisted entries which have been awaiting confirmation for longer than 3 days */
  sql = sqlite3_mprintf("DELETE FROM clients WHERE (86400*(JULIANDAY('NOW')-JULIANDAY(firstseen))<%d) AND (JULIANDAY('NOW')-JULIANDAY(lastseen)>3)", greylist_timeout);
  if(sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK)
    syslog(LOG_WARNING, "database cleanup failed %s: %s", dbpath, sqlite3_errmsg(db));
  sqlite3_free(sql);
}

int callback(void *p, int ncol, char **values, char **colnames)
{
  bool *result = (bool*)p;

  if(result)
    *result = true;

  return 0;
}

bool check_recipient(const char *recipient)
{
  char *sql = NULL;
  bool result = false;

  if(!db || !domain || !recipient)
    return false;

  /* only allow recipient if corresponding triplet was first seen more than greylist_timeout seconds before last time it has been observed */
  sql = sqlite3_mprintf("SELECT ip FROM clients WHERE 86400*(JULIANDAY(lastseen)-JULIANDAY(firstseen))>=%d AND ip='%q' AND domain='%q' AND recipient='%q'", greylist_timeout, peer), domain, recipient);
  if(sqlite3_exec(db, sql, callback, &result, NULL) != SQLITE_OK)
  {	// report error but ignore it
    syslog(LOG_WARNING, "could not access database %s: %s", dbpath, sqlite3_errmsg(db));
  }
  sqlite3_free(sql);

  return result;
}
#endif

#define MSG_TMPL_INVALID_YESNO_OPTION "invalid setting '%s' for '%s', only 'yes' or 'no' is valid"

void configure()
{
  FILE * conf = NULL;
  char line[BUFSIZE+1];
  char * s = NULL;

  conf = fopen(configfile, "r");

  if(conf)
  {
    unsigned int lnum = 0;

    while(fgets (line, BUFSIZE, conf) != NULL)
    {
      lnum++;

      if ((s = strchr(line, '\r')) != NULL) *s = ' ';
      if ((s = strchr(line, '\n')) != NULL) *s = '\0';

      for (s = line; isspace(*s); s++);	/* skip blanks */
      if(isalpha(*s))	/* ignore comments and malformed names */
      {
        char * key = NULL;
        char * value = NULL;

        for ( key = s; isalnum(*s) || *s=='_'; s++) *s = tolower(*s);

        while(isspace(*s)) { *s = '\0'; s++; }
        if(*s != '=')
        {
          syslog(LOG_ERR, "Malformed line in %s:%d", configfile, lnum);
          break;	/* malformed line */
        }
       
        *s = '\0';
        s++;
        while(isspace(*s)) { *s = '\0'; s++; }
        value = s;

        if(strcmp(key, "timeout") == 0)
        {
	  timeout = atoi(value);

          if(timeout <= 0)
          {
            syslog(LOG_ERR, "Invalid timeout %d", timeout);
            timeout = DEF_TIMEOUT;
          }
        }
        else
        if(strcmp(key, "maildirs") == 0)
        {
	  mailboxes = strdup(value);
        }
        else
#ifdef SQLITE
        if(strcmp(key, "database") == 0)
        {
	  dbpath = strdup(value);
        }
        else
        if(strcmp(key, "greylist") == 0)
        {
	  greylist_timeout = atoi(value);

          if(greylist_timeout < 0)	/* 0 is a valid value: no greylisting is done */
          {
            syslog(LOG_ERR, "Invalid timeout %d", greylist_timeout);
            greylist_timeout = DEF_TIMEOUT;
          }
        }
        else
        if(strcmp(key, "old") == 0)
        {
	  greylist_old = atoi(value);

          if(greylist_old < 0)	/* 0 is a valid value: no greylisting is done */
          {
            syslog(LOG_ERR, "Invalid timeout %d days", greylist_old);
            greylist_old = DEF_OLD;
          }
        }
        else
#endif
        if(strcmp(key, "user") == 0)
        {
          struct passwd * pwent = NULL;

          pwent = getpwnam(value);

          if(pwent)
            uid = pwent->pw_uid;
          else
            syslog(LOG_ERR, "Unknown user %s in %s:%d", value, configfile, lnum);
        }
        else
        if(strcmp(key, "group") == 0)
        {
          struct group * grent = NULL;

          grent = getgrnam(value);

          if(grent)
            gid = grent->gr_gid;
          else
            syslog(LOG_ERR, "Unknown group %s in %s:%d", value, configfile, lnum);
        }
        else
        if(strcmp(key, "catchall") == 0)
        {
	  do_catchall = atoi(value) ? 1 : 0;
        }
        else
        if(strcmp(key, "rejectall") == 0)
        {
	  always_refuse = atoi(value) ? 1 : 0;
        }
        else
        if(strcmp(key, "mkmailbox") == 0)
        {
	  auto_mkmaildir = atoi(value) ? 1 : 0;
        }
        else
        if(strcmp(key, "accept_bounces") == 0)
        {
          if(EQ(value, "yes")) accept_bounces = true;
          else if(EQ(value, "no")) accept_bounces = false;
          else syslog(LOG_WARNING, MSG_TMPL_INVALID_YESNO_OPTION, value, key);
        }
        else
        if(strcmp(key, "spf_fail_as_permanent_error") == 0)
        {
          if(EQ(value, "yes")) spf_fail_as_permanent_error = true;
          else if(EQ(value, "no")) spf_fail_as_permanent_error = false;
          else syslog(LOG_WARNING, MSG_TMPL_INVALID_YESNO_OPTION, value, key);
        }
      }
    }
    fclose(conf);
  }
}

void print_cont(int code, const char * msg)
{
    /* sends an smtp reply-continuation message. */
    /* should not be used alone, but close the reply by print(). */
    /* msg must not contain CR/LF. */
    printf("%d-%s\r\n", code, msg);
}

void print(int code, const char * message)
{
  char *newline = NULL;
  char *msg = NULL;

  while((newline = strchr(message, '\n')))
  {
    msg = strndup(message, newline - message);
    print_cont(code, msg);
    free(msg);
    message = newline+1;
  }
  printf("%d %s\r\n", code, message);
  fflush(stdout);

  alarm(timeout);
}

void sigalarm(int s)
{
  if(s == SIGALRM)
  {
    syslog(LOG_INFO, "connection helo=%s [%s] timed out after %d seconds", helo?helo:"<unknown>", peer, timeout);
    print(421, "connection timed out.");
    exit(1);
  }
}

bool readline(char * line)
{
  char * s = NULL;
  bool result = false;

  strcpy(line, "");
  if(fgets (line, BUFSIZE, stdin) != NULL) result = true;

  if ((s = strchr(line, '\n')) != NULL) *s = '\0';
  if ((s = strchr(line, '\r')) != NULL) *s = '\0';

  return result;
}

int verb(char *line)
{
  int i = 0;
  
  for(i=0; i<__UNKNOWN__; i++)
  {
    if((strncasecmp(line, smtp_commands[i], strlen(smtp_commands[i])) == 0) &&
      ((line[strlen(smtp_commands[i])] == '\0') || (line[strlen(smtp_commands[i])] == ' ') || (line[strlen(smtp_commands[i])-1] == ':')))
      return i;
  }

  return __UNKNOWN__;
}

int parse_line(char *line, char **param)
{
  int v = verb(line);

  if(v != __UNKNOWN__)
  {
    *param = line + strlen(smtp_commands[v]);
    while(isblank(*param[0]))
      (*param)++;
  }

  if((*param) && (strlen(*param) == 0))
    *param = NULL;

  return v;
}

char *lowercase(char *s)
{
  size_t i = 0;
  if(!s) return NULL;

  for(i=0; s[i]; i++)
    s[i] = tolower(s[i]);

  return s;
}

int valid(const char *address)
{
  return strchr(address, '@') && strchr(address, '.');
}


char *extract_email(char *param)
{
  char * bra = NULL;
  char * cket = NULL;

  bra = strchr(param, '<');
  cket = strchr(param, '>');

  if(!bra || !cket)
    return NULL;

  if(bra - cket >= 0)
    return NULL;

  *cket = '\0';
  bra++;
  if(!valid(bra))		// check if what we extracted looks like an e-mail address
  {
    *cket = '>';		// it doesn't: put everything back in place and exit
    return NULL;
  }

  return lowercase(strdup(bra));
}

void delay()
{
  struct timespec t;

  if(!badness)
    return;

  t.tv_sec = badness * DELAY;
  t.tv_nsec = 0;

  syslog(LOG_DEBUG, "suspicious client helo=%s [%s], localport=%s, sleeping %d seconds",  helo?helo:"<unknown>", peer, myport, badness * DELAY);
#if SQLITE
  clean_db();
#endif
  nanosleep(&t, NULL);
}

void suspicious(const char *line)
{
  badness++;
  timeout /= 2;		/* be less tolerant with bad clients */

  syslog(LOG_NOTICE, "suspicious client helo=%s [%s], localport=%s, last command: \"%s\"",  helo?helo:"<unknown>", peer, myport, line?line:"");
}

void syntax_error(const char *line)
{
  suspicious(line);
  print(501, "syntax error.");
}

void protocol_error(const char *line)
{
  suspicious(line);
  print(503, "protocol error.");
}

bool impersonate(uid_t u, gid_t g)
{
  setegid(sgid);
  seteuid(suid);
  return (setegid(g)==0) && (seteuid(u)==0);
}

bool raise_privileges()
{
  return (setegid(sgid)==0) && (seteuid(suid)==0);
}

void drop_privileges()
{
  int lasterror = errno;

  if(suid == (uid_t)(-1))
    suid = getuid();
  if(sgid == (gid_t)(-1))
    sgid = getgid();
  impersonate(uid, gid);

  errno = lasterror;
}

void trace_headers(recipient *r)
{
  time_t now;
  char date[BUFSIZE+1];

  if(!r || ferror(r->mailbox))
    return;

  time(&now);
  strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z (%Z)", localtime(&now));
  fprintf(r->mailbox, "Return-Path: <%s>\r\n", mail);
  fprintf(r->mailbox, "Delivered-To: %s\r\n", r->email);
  fprintf(r->mailbox, "Received: from helo=%s [%s]\r\n", helo, peer);
  fprintf(r->mailbox, "\tby %s [%s]:%s with %s (%s %s) id %s\r\n", hostname, myip, myport, esmtp?"ESMTP":"SMTP", PROGRAMNAME, getpackageversion(), id);
  fprintf(r->mailbox, "\tfor %s; %s", r->rcpt_to, date);
  
  if(spf_header[0]!=0) fprintf(r->mailbox, "\r\n%s", spf_header);
}

bool samefile(const char *f1, const char *f2)
{
  struct stat f1s, f2s;

  if((!f1) || (!f2))
    return false;

  if(stat(f1, &f1s) != 0)
    return false;
  if(stat(f2, &f2s) != 0)
    return false;

  return (f1s.st_dev == f2s.st_dev)
	&& (f1s.st_ino == f2s.st_ino);
}

bool in_recipients(char *to)
{
  recipient *r = recipients;

  while(r)
  {
    if(samefile(to, r->email))
    {
      syslog(LOG_INFO, "duplicate message: helo=%s [%s], localport=%s, id=%s, return-path=<%s>, to=<%s>, delivered-to=<%s>", helo, peer, myport, id, mail, to, r->email);
      return true;
    }
    r = r->next;
  }

  return false;
}

bool add_recipient(char *to)
{
  char mailbox[BUFSIZE+1];
  char localpart[BUFSIZE+1];
  char * domainpart = NULL;
  char comm[BUFSIZE+1];
  char * rcpt_to;
  recipient *r = NULL;
  int fd = -1;
  struct stat stats;

  if(strspn(to, SAFECHARS) != strlen(to))	// characters not allowed in mailboxes names
  {
    syslog(LOG_WARNING, "invalid char in RCPT TO: '%s'", to);
    print(553, "rejected");
    return false;
  }

  if(chdir(mailboxes) != 0)
  {
    syslog(LOG_ERR, "can't access %s: %s", mailboxes, strerror(errno));
    print(550, "rejected");
    return false;
  }

  raise_privileges();	/* we must raise privileges because our default user may not be allowed to stat() mailboxes */

  if(in_recipients(to))
  {
    drop_privileges();
    print(250, "recipient OK");
    return false;
  }
  drop_privileges();

  /* save original Recipient */
  rcpt_to = strdup(to);

  stat:

  strcpy(localpart, to);
  domainpart = strrchr(localpart, '@');
  if(domainpart) {
    localpart[domainpart - localpart] = '\0';
    domainpart++;
  }
  //debug//fprintf(stderr, "[%s] [%s] [%s]\n", to, localpart, domainpart);

  raise_privileges();
  if(stat(to, &stats) != 0)
  {
    unsigned int code;
    drop_privileges();
    code = (errno==ENOENT)?550:451;
    syslog(LOG_INFO, "%s helo=%s [%s]: localport=%s, from=<%s>, to=<%s>: %s", code==550?"catch":"reject", helo, peer, myport, mail, to, code==550?"no such mailbox":strerror(errno));
    if(code==550) {
      if(auto_mkmaildir) {
        /* unsafe chars here (single- and double-quote, space, slash) are rejected in <to>, so we're good to go */
      	snprintf(comm, BUFSIZE, "/bin/bash -c '/usr/bin/install -v -o nobody -g mailadmin -m 0750 -d ./\"%s\"/{,new,cur,tmp} >&2'", to);
      	raise_privileges();
      	if(system(comm)==0) {
      	  drop_privileges();
    	  goto stat;
    	}
    	drop_privileges();
      }
      else if(strcmp(to, CATCHALL_LOCALPART)!=0 && do_catchall) {
      	if(strcmp(localpart, CATCHALL_LOCALPART)!=0) {				// try CatchAll@RealDoma.in
      	  sprintf(to, "%s@%s", CATCHALL_LOCALPART, domainpart);
      	  goto stat;
      	}
      	else {									// try global CatchAll
    	  sprintf(to, CATCHALL_LOCALPART);
    	  goto stat;
    	}
      }
    }
    print(code, "no such mailbox");
    return false;
  }
  drop_privileges();

  snprintf(mailbox, BUFSIZE, "%s/tmp/%s-XXXXXX", to, id);
  impersonate(stats.st_uid, stats.st_gid);
  fd = mkstemp(mailbox);
  if(fd >= 0)
    fchmod(fd, stats.st_mode & (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH));
  drop_privileges();

  if(fd < 0)
  {
    syslog(LOG_ERR, "can't create %s: %s", mailbox, strerror(errno));
    print(451, "mailbox unavailable");
    return false;
  }

#if SQLITE
  update_db(to);
  if(!check_recipient(to))
  {
    syslog(LOG_INFO, "greylisted helo=%s [%s]: from=<%s>, to=<%s>", helo, peer, mail, to);
    print(450, "you are being put on waiting list, come back later");
    deferred_recipients++;
    return false;
  }
#endif

  r = (recipient*)malloc(sizeof(*r));

  r->email = to;
  r->rcpt_to = rcpt_to;
  r->mboxname = strdup(mailbox);
  r->mailbox = fdopen(fd, "w");
  r->uid = stats.st_uid;
  r->gid = stats.st_gid;
  r->good = true;
  r->next = recipients;

  trace_headers(r);

  recipients = r;

  print(250, "recipient OK");
  valid_recipients++;

  return true;
}

bool free_recipients()
{
  bool overall_result = true;
  int try = 0;
  bool ok_write, ok_close, ok_link;
  char mailbox[BUFSIZE+1];
  recipient *r = recipients;

  while(r)
  {
    recipient *t = r;

    overall_result = overall_result && (!ferror(r->mailbox));
    overall_result = overall_result && r->good;
    ok_write = r->good;
    ok_close = true;
    ok_link = true;
    if(r->mailbox)
    {
      int ok = fclose(r->mailbox);
      if(ok != 0)
      {
		syslog(LOG_ERR, "fclose: %s: %s", r->mboxname, strerror(errno));
		ok_close = false;
		overall_result = false;
      }
    }
    if(r->mboxname)
    {
      bool failed_linking = false;
      try = 0;
      impersonate(r->uid, r->gid);
      if(size)
      do
      {
        if(try == 0)
          snprintf(mailbox, BUFSIZE, "%s/new/%s", r->email, id);
        else
          snprintf(mailbox, BUFSIZE, "%s/new/%s-%d", r->email, id, try);
        try++;
      } while ((failed_linking = ((link(r->mboxname, mailbox) != 0)) && (try<MAXTRY)));


      failed_linking = failed_linking || (try >= MAXTRY);
      ok_link = !failed_linking;
      overall_result = overall_result && ok_link;

      if(size)
      {
        if(ok_write && ok_close && ok_link)
          syslog(LOG_INFO, "message delivered: helo=%s [%s], localport=%s, id=%s, return-path=<%s>, to=<%s>, size=%d", helo, peer, myport, id, mail, r->email, size);
        else
          syslog(LOG_INFO, "failed to deliver message: helo=%s [%s], localport=%s, id=%s, return-path=<%s>, to=<%s>, size=%d: %s", helo, peer, myport, id, mail, r->email, size, strerror(errno));
      }
      unlink(r->mboxname);
      drop_privileges();
      free(r->mboxname);
    }
    if(r->email) free(r->email);

    r = r->next;
    free(t);
  }

  recipients = NULL;
  return overall_result;
}

void send_char_to_recipients(char c)
{
  recipient *r = recipients;

  while(r)
  {
    if(!ferror(r->mailbox) && r->good)
    {
      size_t written = fwrite(&c, 1, 1, r->mailbox);
      if(written != 1)
      {
		syslog(LOG_ERR, "fwrite: %s: %s", r->mboxname, strerror(errno));
      	r->good = false;
      }
    }
    r = r->next;
  }

  size++;
}

void retrieve_data()
{
  int eompos = 2;	/* skip <CR><LF> as .<CR><LF> is a valid (albeit empty) message */
  int c = 0;
  int i = 0;

  size = 0;
  print(354, "enter message, end with \".\" on a line by itself");

  /* read data until we get an error or EOM (<CR><LF>.<CR><LF>) */
  while((eompos < strlen(EOM)) && ((c=getchar()) != EOF))
  {
    if(c == EOM[eompos])
      eompos++;
    else
    {
      for(i=0; i<eompos; i++)
        send_char_to_recipients(EOM[i]);

      if((c != EOM[0]) && ((c != '.') || (eompos != 3)))	/* transform <CR><LF>.. into <CR><LF>. */
        send_char_to_recipients(c);

      eompos = (c == EOM[0])?1:0;
    }

    alarm(timeout);
  }

  send_char_to_recipients('\r');
  send_char_to_recipients('\n');

  if(free_recipients()) {
     if(always_refuse)
       print(502, "failed to deliver message.");
     else
       print(250, "accepted for delivery.");
     }
  else {
     if(always_refuse)
       print(502, "failed to deliver message.");
     else {
       size = 0;
       print(451, "failed to deliver message.");
     }
  }
}

void newid()
{
  snprintf(id, sizeof(id), "%lx-%x", time(NULL), getpid());
}

void cleanup()
{
  free_recipients();
  if(mail)
    free(mail);
  mail = NULL;
  domain = NULL;	/* do not free() domain as it actually points to mail */
  esmtp = false;
  size = 0;
  newid();
}

void usage()
{
  fprintf(stderr, "usage: %s [-V | -c FILE]\n -V  version\n -c  config file\n", PROGRAMNAME);
  exit(1);
}

int spf_query(const char* ip, const char* helo, const char* mailfrom, int* code_p, char* result_str, char* answer, char* logtext, char* header)
{
	pid_t kid;
	char spf_info[BUFSIZE+1];
	char outbuf[BUFSIZE+1];
	int spf_info_len;
	int pd0[2];
	int pd1[2];
	//FILE* reader0;
	//FILE* writer0;
	FILE* reader1;
	//FILE* writer1;
	char* spf_cmd = "spfquery";
	char* spf_arg_list[] = {
		spf_cmd,     /* argv[0], the name of the program. */
		"-f", "-", NULL
	};
	*code_p = 6;
	sprintf(result_str, "%s", "error");
	sprintf(logtext, "%s: exec failed", spf_cmd);
	sprintf(answer, "%s", "temporary error");
	sprintf(header, "%s", "");
	int in_error_block = 0;
	int line_no = 0;
	
	pipe(pd0);	// smtpd -> spfquery
	pipe(pd1);	// spfquery -> smtpd
	//reader0 = fdopen(pd0[0], "r");
	//writer0 = fdopen(pd0[1], "w");
	reader1 = fdopen(pd1[0], "r");
	//writer1 = fdopen(pd1[1], "w");
	
	kid = fork();
	if(kid == 0)
	{
		close(pd0[1]);
		close(pd1[0]);
		dup2(pd0[0], fileno(stdin));
		dup2(pd1[1], fileno(stdout));
		execvp(spf_cmd, spf_arg_list);
		_exit(127);
	}
	else if(kid == -1)
	{
		syslog(LOG_ERR, "fork() failed");
		return 0;
	}

	close(pd0[0]);
	close(pd1[1]);
	spf_info_len = sprintf(spf_info, "%s %s %s\n", ip, mailfrom, helo);
	//fprintf(writer0, "%s", spf_info);	// doesnt work
	write(pd0[1], spf_info, spf_info_len);
	close(pd0[1]);
	
	start_results:
	if(!fgets(outbuf, sizeof outbuf, reader1)) goto end_results;
	while(outbuf[strlen(outbuf)-1] == 10 || outbuf[strlen(outbuf)-1] == 13) outbuf[strlen(outbuf)-1] = 0;
	if(strncmp(outbuf, "StartError", 10)==0) {
		in_error_block = 1;
		syslog(LOG_WARNING, "spfquery args: %s %s %s:", ip, mailfrom, helo);
	}
	if(in_error_block) {
		syslog(LOG_WARNING, "spfquery: %s", outbuf);
	} else {
		line_no++;
		if(line_no == 1) snprintf(result_str, 10, "%s", outbuf);
		else if(line_no == 2) sprintf(answer, "%s", outbuf);
		else if(line_no == 3) sprintf(logtext, "%s", outbuf);
		else if(line_no == 4) sprintf(header, "%s", outbuf);
	}
	if(strncmp(outbuf, "EndError", 8)==0) in_error_block = 0;
	goto start_results;
	
	end_results:
	
	wait(code_p);
	*code_p = WEXITSTATUS(*code_p);
	/*  spfquery return codes:
	1 neutral	The sender domain explicitly makes no assertion about the ip-address.  This result must be interpreted exactly as if no SPF record at all existed.
	2 pass		The ip-address is authorized to send mail for the sender domain.
	3 fail		The ip-address is unauthorized to send mail for the sender domain.
	4 softfail	The ip-address is not authorized to send mail for the sender domain, but the sender domain cannot or does not wish to make a strong assertion that no such mail can ever come from it.
	5 none		No SPF record was found.
	6 error (temporary)		A transient error occurred (e.g. failure to reach a DNS server), preventing a result from being reached.
	7 unknown (permanent error)	One or more SPF records could not be interpreted.
	0 other errors, eg. invalid record
	*/
	if(answer[0]==0) sprintf(answer, "spf verify %s", result_str);
	if(*code_p == 1 || *code_p == 2 || *code_p == 5 || /* "~all" gives softfail */ *code_p == 4) return 1;
	return 0;
}


char * load_mailname()
{
	FILE * fh;
	
	fh = fopen("/etc/mailname", "r");
	if(fh != NULL)
	{
		fgets(mailname, sizeof(mailname), fh);
		fclose(fh);
		goto mailname_ok;
	}
	snprintf(mailname, sizeof(mailname), hostname);
	mailname_ok:
	return mailname;
}


int main(int argc, char * * argv)
{
  socklen_t length;
  char line[BUFSIZE+1];
  int c = 0;
  int version = 0;
  char p[BUFSIZE+1];
  
  int spf_code;
  char spf_result_str[10];
  char spf_answer[BUFSIZE+1];
  char spf_logtext[BUFSIZE+1];
  spf_header[0] = 0;
  char banner[BUFSIZE+1];
  
  while ((c = getopt(argc, argv, "Vc:")) != -1)
   switch (c)
    {
    case 'V':                   /* display version */
      version = 1;
      break;
    case 'c':
      configfile = optarg;
      break;
    default:
      usage();
      return 1;
    }

  argc -= optind;
  argv += optind;

  if (argc != 0)
    usage();

  if(version)
  {
    printf("%s\n", getpackageversion());
    exit(0);
  }

  openlog(argv[0], LOG_PID, LOG_MAIL);
  configure();

  drop_privileges();

  signal(SIGALRM, sigalarm);

  newid();
  
  if(gethostname(hostname, sizeof(hostname)) != 0)
    snprintf(hostname, sizeof(hostname), "localhost");

  sprintf(myip, "%s", "<unknown>");
  sprintf(myport, "%s", "???");

  length = sizeof(remote_end);
  if(getsockname(0, (struct sockaddr*)&remote_end, &length) == 0)
  {
    sprintf(myip, "%s", inet_ntop(AF_INET, &remote_end.sin_addr, myip, 16));
    snprintf(myport, 6, "%d", ntohs(remote_end.sin_port));
  }
  
  if(getenv("TCPLOCALPORT") != NULL)
  {
    snprintf(myport, 6, "%s", getenv("TCPLOCALPORT"));
  }
  
  peer = getenv("REMOTE_HOST");
  if(peer == NULL)
  {
    peer = getenv("TCPREMOTEIP");
    if(peer == NULL)
    {
      if(getpeername(0, (struct sockaddr*)&remote_end, &length) == 0)
      {
        sprintf(p, "%s", inet_ntoa(remote_end.sin_addr));
        peer = p;
      }
    }
  }
  
  if(peer != NULL)
  {
    syslog(LOG_INFO, "connection from [%s] localport=%s", peer, myport);
#ifdef SQLITE
    open_db();
#endif
    load_mailname();
    snprintf(banner, sizeof(banner), "norelaysmtpd on %s is ready.", mailname);
    print(220, banner);

    while(readline(line))
    {
      int cmd = __UNKNOWN__;
      char * param = NULL;

      fflush(stdout);
      delay();		/* take our time if it's a bad client */

      cmd = parse_line(line, &param);

      switch(cmd)
      {
        case HELO:
          if(param && strchr(param, ' ') == NULL)
          {
            if(helo) free(helo);
            helo = strdup(param);
            print(250, mailname);
          }
          else
            syntax_error(line);
          break;

        case EHLO:
          if(param && strchr(param, ' ') == NULL)
          {
            if(helo) free(helo);
            helo = strdup(param);
            esmtp = 1;
            print_cont(250, mailname);
            print(250, "8BITMIME");
          }
          else
            syntax_error(line);
          break;

        case RSET:
          if(param)
            syntax_error(line);
          else
          {
            cleanup();
            print(250, "OK");
          }
          break;

        case EXPN:
          suspicious(line);
          if(!param)
            syntax_error(line);
          else
          {
            print(252, "disabled");
          }
          break;

        case VRFY:
          suspicious(line);
          if(!param)
            syntax_error(line);
          else
          {
            print(252, "disabled");
          }
          break;

        case XCLIENT:
          if(!param)
            syntax_error(line);
          else
          {
            /* TODO generalize, put these in config parameters */
            if(EQ(peer, "127.0.0.1") && EQ(myport, "8025"))
            {
              char xclient_addr[INET6_ADDRSTRLEN+1];
              char xclient_name[128];
              #define STRINGIFY(x) #x
              #define TOSTR(x) STRINGIFY(x)
              if(sscanf(param, "ADDR=%" TOSTR(INET6_ADDRSTRLEN) "s NAME=%127s", xclient_addr, xclient_name) == 2)
              {
              	peer = xclient_addr;
              	// TODO extract myport from xclient_name
              }
              print(250, "OK");
            }
            else
            {
              print(503, "not trusted.");
            }
          }
          break;
        
        case NOOP:
          if(param)
            syntax_error(line);
          else
          {
            print(250, "OK");
          }
          break;

        case HELP:
          suspicious(line);
            if(!param)
              print(214, "supported commands:\n    HELO    EHLO    MAIL    RCPT    DATA\n    RSET    NOOP    QUIT    HELP    VRFY\n    EXPN");
            else
              print(504, "use \"HELP\" to get a list of supported commands.");
          break;

        case MAIL:
          if(!mail && helo && param)
          {
            if((mail = extract_email(param))) 
            {
                int response_code;
                spf_code = 0;
                spf_query(peer, helo, mail, &spf_code, spf_result_str, spf_answer, spf_logtext, spf_header);
                
                switch(spf_code)
                {
                    case SPF_CODE_PASS:
                    case SPF_CODE_NEUTRAL:
                    case SPF_CODE_SOFTFAIL:
                    case SPF_CODE_NONE:
                        if(spf_header[0] == 0) sprintf(spf_header, "Received-SPF: %s", spf_result_str);
                        
                        domain = strrchr(mail, '@');    /* point to sender's domain name */
                        if(domain) domain++;
                        print(250, "sender OK");
                    break;
                    
                    default:
                        response_code = 451;
                        if(spf_fail_as_permanent_error && spf_code == SPF_CODE_FAIL) response_code = 550;
                        
                        syslog(LOG_WARNING, "reject helo=%s [%s] localport=%s, mail_from=<%s>: %s (%s)", helo, peer, myport, mail, spf_logtext, spf_result_str);
                        mail = NULL;
                        print(response_code, spf_answer);
                    break;
                }
            }
            else if(accept_bounces && EQ(param, "<>"))
            {
                // it's a bounce and we want it
                mail = strdup("");
                print(250, "gimme that bounce");
            }
            else
            {
              suspicious(line);
              syslog(LOG_INFO, "reject helo=%s [%s] localport=%s: invalid return-path: %s", helo, peer, myport, mail);
              print(501, "invalid return-path");
            }
          }
          else
          {
            if(!param)
              syntax_error(line);
            else
              protocol_error(line);
          }
          break;

        case RCPT:
          if(mail && helo && param)
          {
            char *to = NULL;

            if((to = extract_email(param)))
            {
              add_recipient(to);
            }
            else
            {
              invalid_recipients++;
              print(553, "invalid address");
            }
          }
          else
          {
            if(!param)
              syntax_error(line);
            else
              protocol_error(line);
          }
          break;

        case DATA:
          if(recipients && mail && helo && !param)
          {
            retrieve_data();
            cleanup();
          }
          else
          {
            if(param)
              syntax_error(line);
            else
              protocol_error(line);
          }
          break;

        case QUIT:
          if(param)
            syntax_error(line);
          else
          {
            syslog(LOG_INFO, "client helo=%s [%s] disconnected localport=%s recipients=%d (%d valid, %d deferred).",  helo?helo:"<unknown>", peer, myport, valid_recipients+invalid_recipients+deferred_recipients, valid_recipients, deferred_recipients);
            cleanup();
            print(221, "bye.");
#ifdef SQLITE
            close_db();
#endif
            return 0;
          }
          break;

        default:
          protocol_error(line);
      }
    }
    syslog(LOG_NOTICE, "client helo=%s [%s] localport=%s dropped connection.", helo?helo:"<unknown>", peer, myport);
#ifdef SQLITE
    clean_db();
    badclient_db();
#endif
  }
  else
  {
    syslog(LOG_ERR, "can't get remote address");
    print(554, "don't know who you are.");
  }

  closelog();
#ifdef SQLITE
  close_db();
#endif
  return 0;

  (void) &id;    /* avoid warning "id defined but not used" */
}
