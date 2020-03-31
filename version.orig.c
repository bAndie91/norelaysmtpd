#include "version.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char versiontag[] = "@(#) $URL: http://dev.ezix.org/source/packages/smtpd/releases/T.00.02/version.c $ >";

const char *getpackageversion()
{
  char * releasename = NULL;
  char * lastslash = NULL;

  releasename = strdup(versiontag);

  lastslash = strrchr(releasename, '/');
  if(lastslash)
  {
    *lastslash = '\0';	// cut the basename off

    lastslash = strrchr(releasename, '/');
  }

  if(lastslash)
  {
    free(releasename);
    return lastslash+1;
  }
  else
  {
    free(releasename);
    return "unknown";
  }
}
