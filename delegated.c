#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Draft WeeChat-side implementation of the SASL DELEGATED mechanism
 *
 */

char *
irc_sasl_mechanism_ecdsa_nist256p_challenge_delegated (const char *,
                                                       const char *,
                                                       const char *);


int main(void) {
    const char *sasl_agent  = "python agent.py";
    const char *sasl_key    = "user";
    const char *data_base64 = "challenge";

    char *response;
    response = irc_sasl_mechanism_ecdsa_nist256p_challenge_delegated (sasl_agent,
                                                                      sasl_key,
                                                                      data_base64);
    printf("response:\n\t\"%s\"\n", response);
    return 0;
}

char *
irc_sasl_mechanism_ecdsa_nist256p_challenge_delegated (const char *sasl_agent,
                                                       const char *sasl_key,
                                                       const char *data_base64)
{
    int command_len, response_len, len;
    char *command, *response;
    FILE *fp;

    /* construct command string */
    command_len = strlen (sasl_agent) + strlen (sasl_key) + strlen (data_base64) + 3;
    command = malloc (command_len);
    len = snprintf (command, command_len, "%s %s %s", sasl_agent, sasl_key, data_base64);
    if (len > command_len)
    {
        printf ("[error] failed to construct delegation command");
        free (command);
        return NULL;
    }

    /* start an agent program and open pipe to its STDOUT */
    if ((fp = popen (command, "r")) == NULL)
    {
        printf ("[error] cannot open pipe");
        free (command);
        return NULL;
    }

    /* allocate response buffer and read agent's output to it */
    /* TODO: somehow get signature length */
    response_len = 32;
    response = malloc (response_len);
    fgets (response, response_len, fp);

    /* cleanup open pipe and allocated command buffer */
    free (command);
    if (pclose (fp))
    {
        printf ("[error] not found or exited with error");
        free (response);
        return NULL;
    }

    /* trim trailing newlines and return response */
    response[strcspn(response, "\r\n")] = '\0';
    return response;
}
