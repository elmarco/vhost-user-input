#include <glib.h>
#include <systemd/sd-journal.h>

static GLogFunc old_handler;

static void
journal_log_handler(const gchar *log_domain,
                    GLogLevelFlags log_level,
                    const gchar *message,
                    gpointer user_data)
{
  gboolean to_journal = TRUE;
  int priority;
  const gchar *domains;

  switch (log_level & G_LOG_LEVEL_MASK) {
  case G_LOG_LEVEL_ERROR:
      priority = LOG_CRIT;
      break;
  case G_LOG_LEVEL_CRITICAL:
      priority = LOG_CRIT;
      break;
  case G_LOG_LEVEL_WARNING:
      priority = LOG_ERR;
      break;
  case G_LOG_LEVEL_MESSAGE:
  default:
      priority = LOG_WARNING;
      break;
  case G_LOG_LEVEL_INFO:
      priority = LOG_INFO;
      break;
  case G_LOG_LEVEL_DEBUG:
      domains = g_getenv("G_MESSAGES_DEBUG");
      if (domains == NULL ||
          (strcmp(domains, "all") != 0 && (!log_domain || !strstr(domains, log_domain)))) {
          to_journal = FALSE;
      }
      priority = LOG_INFO;
      break;
  }

  if (to_journal) {
      sd_journal_send("MESSAGE=%s", message,
                      "PRIORITY=%d", (int)priority,
                      "GLOG_DOMAIN=%s", log_domain ? log_domain : "",
                      NULL);
  }

  if (old_handler)
      old_handler(log_domain, log_level, message, NULL);
}

void set_journal_log_handler(void)
{
    old_handler = g_log_set_default_handler(journal_log_handler, NULL);
}
