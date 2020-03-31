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
#define SAFECHARS "@0123456789-._abcdefghijklmnopqrstuvwxyz"

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
	NULL};

typedef struct _to {
	char *email;
	char *mboxname;
	FILE *mailbox;
	uid_t uid;
	gid_t gid;
	struct _to *next;
	} recipient;

static char * configfile = SYSCONFDIR"/smtpd.conf";
static uid_t uid = (uid_t)(-1);
static gid_t gid = (gid_t)(-1);
static uid_t suid = (uid_t)(-1);
static gid_t sgid = (gid_t)(-1);
static char hostname[BUFSIZE] = "localhost";
static char * mailboxes = DATADIR"/mailboxes";
#ifdef SQLITE
static char * dbpath = DATADIR"/cache/smtpd/db";
static sqlite3 * db = NULL;
static unsigned int greylist_timeout = DEF_TIMEOUT;
static unsigned int greylist_old = DEF_OLD;
#endif
static struct sockaddr_in remote;
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
  sql = sqlite3_mprintf("INSERT OR IGNORE INTO clients (ip,domain,recipient) VALUES ('%q', '%q', '%q') ; UPDATE OR IGNORE clients SET lastseen=CURRENT_TIMESTAMP WHERE ip='%q' AND domain='%q' AND recipient='%q'", inet_ntoa(remote.sin_addr), domain, recipient, inet_ntoa(remote.sin_addr), domain, recipient);
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

  sql = sqlite3_mprintf("DELETE FROM clients WHERE ip='%q'", inet_ntoa(remote.sin_addr));
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
  sql = sqlite3_mprintf("SELECT ip FROM clients WHERE 86400*(JULIANDAY(lastseen)-JULIANDAY(firstseen))>=%d AND ip='%q' AND domain='%q' AND recipient='%q'", greylist_timeout, inet_ntoa(remote.sin_addr), domain, recipient);
  if(sqlite3_exec(db, sql, callback, &result, NULL) != SQLITE_OK)
  {	// report error but ignore it
    syslog(LOG_WARNING, "could not access database %s: %s", dbpath, sqlite3_errmsg(db));
  }
  sqlite3_free(sql);

  return result;
}
#endif

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

        for ( key = s; isalnum(*s); s++) *s = tolower(*s);

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
      }
    }
    fclose(conf);
  }
}

void print(int code, const char * message)
{
  char *newline = NULL;
  char *msg = NULL;

  while((newline = strchr(message, '\n')))
  {
    msg = strndup(message, newline - message);
    printf("%d-%s\r\n", code, msg);
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
    syslog(LOG_INFO, "connection with %s [%s] timed out after %d seconds", helo?helo:"<unknown>", inet_ntoa(remote.sin_addr), timeout);
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

  syslog(LOG_DEBUG, "suspicious client %s [%s], sleeping %d seconds",  helo?helo:"<unknown>", inet_ntoa(remote.sin_addr), badness * DELAY);
#if SQLITE
  clean_db();
#endif
  nanosleep(&t, NULL);
}

void suspicious(const char *line)
{
  badness++;
  timeout /= 2;		/* be less tolerant with bad clients */

  syslog(LOG_NOTICE, "suspicious client %s [%s], last command: \"%s\"",  helo?helo:"<unknown>", inet_ntoa(remote.sin_addr), line?line:"");
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
  fprintf(r->mailbox, "Received: from %s [%s]\r\n", helo, inet_ntoa(remote.sin_addr));
  fprintf(r->mailbox, "\tby %s with %s (smtpd %s) id %s\r\n", hostname, esmtp?"ESMTP":"SMTP", getpackageversion(), id);
  fprintf(r->mailbox, "\tfor %s; %s", r->email, date);
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
      syslog(LOG_INFO, "duplicate message: from %s [%s], id=%s, return-path=<%s>, to=<%s>, delivered-to=<%s>", helo, inet_ntoa(remote.sin_addr), id, mail, to, r->email);
      return true;
    }
    r = r->next;
  }

  return false;
}

bool add_recipient(char *to)
{
  char mailbox[BUFSIZE+1];
  recipient *r = NULL;
  int fd = -1;
  struct stat stats;

  if(strspn(to, SAFECHARS) != strlen(to))	// characters not allowed in mailboxes names
  {
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

  if(stat(to, &stats) != 0)
  {
    unsigned int code;
    drop_privileges();
    code = (errno==ENOENT)?550:451;
    syslog(LOG_INFO, "reject %s [%s]: from=<%s>, to=<%s>: %s", helo, inet_ntoa(remote.sin_addr), mail, to, code==550?"no such mailbox":strerror(errno));
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
    syslog(LOG_INFO, "greylisted %s [%s]: from=<%s>, to=<%s>", helo, inet_ntoa(remote.sin_addr), mail, to);
    print(450, "you are being put on waiting list, come back later");
    deferred_recipients++;
    return false;
  }
#endif

  r = (recipient*)malloc(sizeof(*r));

  r->email = to;
  r->mboxname = strdup(mailbox);
  r->mailbox = fdopen(fd, "w");
  r->uid = stats.st_uid;
  r->gid = stats.st_gid;
  r->next = recipients;

  trace_headers(r);

  recipients = r;

  print(250, "recipient OK");
  valid_recipients++;

  return true;
}

bool free_recipients()
{
  bool result = true;
  int try = 0;
  bool failed = false;
  char mailbox[BUFSIZE+1];
  recipient *r = recipients;

  while(r)
  {
    recipient *t = r;

    result = result && (!ferror(r->mailbox));
    failed = false;
    if(r->mailbox)
      fclose(r->mailbox);
    if(r->mboxname)
    {
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
      } while ((failed = ((link(r->mboxname, mailbox) != 0)) && (try<MAXTRY)));

      failed = failed || (try >= MAXTRY);
      result = result && (!failed);

      if(size)
      {
        if(failed)
          syslog(LOG_INFO, "failed to deliver message: from %s [%s], id=%s, return-path=<%s>, to=<%s>, size=%d: %s", helo, inet_ntoa(remote.sin_addr), id, mail, r->email, size, strerror(errno));
        else
          syslog(LOG_INFO, "message delivered: from %s [%s], id=%s, return-path=<%s>, to=<%s>, size=%d", helo, inet_ntoa(remote.sin_addr), id, mail, r->email, size);
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
  return result;
}

void send_char_to_recipients(char c)
{
  recipient *r = recipients;

  while(r)
  {
    if(!ferror(r->mailbox))
      fwrite(&c, 1, 1, r->mailbox);
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

  if(free_recipients())
    print(250, "accepted for delivery.");
  else
  {
    size = 0;
    print(451, "failed to deliver message.");
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
  fprintf(stderr, "usage: %s [-V ] [-c FILE]\n\n", "smtpd");
  exit(1);
}


int main(int argc, char * * argv)
{
  socklen_t length;
  char line[BUFSIZE+1];
  int c = 0;
  int version = 0;

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

  length = sizeof(remote);
  if(getpeername(0, (struct sockaddr*)&remote, &length) == 0)
  {
    syslog(LOG_INFO, "connection from [%s]", inet_ntoa(remote.sin_addr));
#ifdef SQLITE
    open_db();
#endif
    print(220, "ready.");

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
          if(param)
          {
            if(helo)
              free(helo);
            helo = strdup(param);
            print(250, "pleased to meet you");
          }
          else
            syntax_error(line);
          break;

        case EHLO:
          if(param)
          {
            if(helo)
              free(helo);
            helo = strdup(param);
            esmtp = 1;
            print(250, "pleased to meet you\n8BITMIME");
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
              domain = strrchr(mail, '@');	/* point to sender's domain name */
              if(domain)
                domain++;
              print(250, "sender OK");
            }
            else
            {
              suspicious(line);
              syslog(LOG_INFO, "reject %s [%s]: invalid return-path", helo, inet_ntoa(remote.sin_addr));
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
            syslog(LOG_INFO, "client %s [%s] disconnected. %d %s (%d valid, %d deferred).",  helo?helo:"<unknown>", inet_ntoa(remote.sin_addr), valid_recipients+invalid_recipients+deferred_recipients, (valid_recipients+invalid_recipients>1)?"recipients":"recipient", valid_recipients, deferred_recipients);
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
    syslog(LOG_NOTICE, "client %s [%s] dropped connection.",  helo?helo:"<unknown>", inet_ntoa(remote.sin_addr));
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

  (void) &id;	/* avoid warning "id defined but not used" */
}
