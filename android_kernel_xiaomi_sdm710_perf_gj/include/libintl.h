#ifndef PERF_GJ_LIBINTL_H
#define PERF_GJ_LIBINTL_H

#ifdef __cplusplus
extern "C" {
#endif

static inline char *gettext(const char *msgid)
{
	return (char *) msgid;
}

static inline char *dgettext(const char *domainname, const char *msgid)
{
	(void) domainname;
	return (char *) msgid;
}

static inline char *dcgettext(const char *domainname, const char *msgid,
			      int category)
{
	(void) domainname;
	(void) category;
	return (char *) msgid;
}

static inline char *ngettext(const char *msgid1, const char *msgid2,
			     unsigned long int n)
{
	return (char *) (n == 1 ? msgid1 : msgid2);
}

static inline char *dngettext(const char *domainname, const char *msgid1,
			      const char *msgid2, unsigned long int n)
{
	(void) domainname;
	return (char *) (n == 1 ? msgid1 : msgid2);
}

static inline char *textdomain(const char *domainname)
{
	return (char *) domainname;
}

static inline char *bindtextdomain(const char *domainname,
				   const char *dirname)
{
	(void) domainname;
	return (char *) dirname;
}

static inline char *bind_textdomain_codeset(const char *domainname,
					    const char *codeset)
{
	(void) domainname;
	return (char *) codeset;
}

#ifdef __cplusplus
}
#endif

#endif
