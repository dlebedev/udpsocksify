#include "udps.h"
#include <libconfig.h>

int parse_configuration_file(FILE *configuration_fd, struct udps_config_t **config_struct) {
    config_t cfg = {};
    config_setting_t *setting, *root;
    const char *nat_ip, *socks5_ip, *client_ip, *user, *password, *name;
    int socks5_port, auth_method, queue_internal, queue_internal2, queue_external;
    unsigned int count;
    struct in_addr addr = {};
    struct udps_config_t *current_config_struct, *previous_config_struct;
    
    if (*config_struct) {
        fprintf(stderr, "config structure was filled before\n");
        return ERR;
    }
    config_init(&cfg);
    if (!config_read(&cfg, configuration_fd)) {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
                config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return ERR;
    }
    
    setting = config_lookup(&cfg, "default");
    if (!setting) {
        fprintf(stderr, "Parse error: not found 'default' section\n");
        config_destroy(&cfg);
        return ERR;
    }
    
    if (!(config_setting_lookup_int(setting, "queue_internal", &queue_internal)
          && config_setting_lookup_int(setting, "queue_external", &queue_external)
          && config_setting_lookup_int(setting, "queue_internal2", &queue_internal2))) {
        fprintf(stderr, "Configuration file does not contain queue_internal, queue_internal2 or queue_external in 'default' section\n");
        config_destroy(&cfg);
        return ERR;
    }
    
    if (!(config_setting_lookup_string(setting, "nat_ip", &nat_ip)
          && config_setting_lookup_string(setting, "socks5_ip", &socks5_ip))) {
        fprintf(stderr, "Configuration file does not contain nat_ip or socks5_ip in 'default' section\n");
        config_destroy(&cfg);
        return ERR;
    }
    if (!config_setting_lookup_int(setting, "socks5_port", &socks5_port))
        socks5_port = 1080;
    if (!config_setting_lookup_int(setting, "auth_method", &auth_method))
        auth_method = 0;
    if (auth_method && !(config_setting_lookup_string(setting, "user", &user)
                         && config_setting_lookup_string(setting, "password", &password))) {
        fprintf(stderr, "In 'default' section of configuration file auth_method setted to 1 but user or password not setted\n");
        config_destroy(&cfg);
        return ERR;
    }
    
    *config_struct = malloc(sizeof(struct udps_config_t));
    memset(*config_struct, 0x0, sizeof(struct udps_config_t));
    (*config_struct)->name = strdup("default");
    
    (*config_struct)->queue_internal = queue_internal;
    (*config_struct)->queue_internal2 = queue_internal2;
    (*config_struct)->queue_external = queue_external;
    
    if (inet_aton(socks5_ip, &addr) > 0)
        (*config_struct)->connect_ip = addr.s_addr;
    else {
        /* Its a problem! We need to shutdown */
        fprintf(stderr, "Configuration file 'default' section: socks5_ip value are not valid ip-address\n");
        free(config_struct);
        return ERR;
    }
    (*config_struct)->connect_port = socks5_port;
    
    if (inet_aton(nat_ip, &addr) > 0)
        (*config_struct)->nat_ip = addr.s_addr;
    else {
        /* Its a problem! We need to shutdown */
        fprintf(stderr, "Configuration file 'default' section: nat_ip value are not valid ip-address\n");
        free(*config_struct);
        return ERR;
    }
        
    (*config_struct)->auth_method = auth_method;
        
    if (auth_method) {
        (*config_struct)->user = (char *)user;
        (*config_struct)->passwd = (char *)password;
    }
    
    previous_config_struct = *config_struct;
    
    /* Read all another sections */
    root = config_root_setting(&cfg);
    count = config_setting_length(root);
    
    for (unsigned int i = 0; i < count; ++i) {
        setting = config_setting_get_elem(root, i);
        
        nat_ip = NULL;
        socks5_ip = NULL;
        client_ip = NULL;
        socks5_port = 0;
        auth_method = 0;
        name = NULL;
        user = NULL;
        password = NULL;

        name = config_setting_name(setting);
        if (name == NULL) {
            /* Unnamed section - skip */
            continue;
        }
        
        if (strcmp(name, "default") == 0)
    	    continue; /* Its default section */
        
        config_setting_lookup_string(setting, "client_ip", &client_ip);
        if (socks5_ip == NULL) {
    	    /* Not specified client_ip - skip this section with warning */
    	    fprintf(stderr, "Configuration file '%s' section: client_ip value not specified but required. Skipped...\n", name);
    	    continue;
    	}
    	
    	if (inet_aton(client_ip, &addr) > 0) {
    	    /* client_ip is not valid ip address - skip this section with warning */
    	    fprintf(stderr, "Configuration file '%s' section: client_ip value specified but not valid ip address. Skipped...\n", name);
    	    continue;
        }
        
        config_setting_lookup_string(setting, "nat_ip", &nat_ip);
        config_setting_lookup_string(setting, "socks5_ip", &socks5_ip);
        
        if (!config_setting_lookup_int(setting, "socks5_port", &socks5_port))
            socks5_port = (*config_struct)->connect_port;
        
        if (!config_setting_lookup_int(setting, "auth_method", &auth_method))
            auth_method = (*config_struct)->auth_method;
        
        if (auth_method && !(config_setting_lookup_string(setting, "user", &user)
                             && config_setting_lookup_string(setting, "password", &password))) {
            user = NULL;
            password = NULL;
        }
        
        current_config_struct = malloc(sizeof(struct udps_config_t));
        memset(current_config_struct, 0x0, sizeof(struct udps_config_t));
        
        if (socks5_ip == NULL)
            current_config_struct->connect_ip = (*config_struct)->connect_ip;
        else {
            if (inet_aton(socks5_ip, &addr) > 0)
                current_config_struct->connect_ip = addr.s_addr;
            else {
                free(current_config_struct);
                continue;
            }
        }
        current_config_struct->connect_port = socks5_port;
        
        if (nat_ip == NULL)
            current_config_struct->nat_ip = (*config_struct)->nat_ip;
        else {
            if (inet_aton(nat_ip, &addr) > 0)
                current_config_struct->nat_ip = addr.s_addr;
            else {
                free(current_config_struct);
                continue;
            }
        }
        
        current_config_struct->name = strdup(name);
        
        current_config_struct->auth_method = auth_method;
        
        if (auth_method && user && password) {
            current_config_struct->user = (char *)user;
            current_config_struct->passwd = (char *)password;
        }
        else
            current_config_struct->auth_method = 0; /* Maybe wrong setting... */
        
        previous_config_struct->next = current_config_struct;
        previous_config_struct = current_config_struct;
    }
    printf("All done!\n");
    config_destroy(&cfg);
    return OK;
}

void release_config(struct udps_config_t *conf) {
    void *tmp;
    
    tmp = (void *)conf->name;
    if (tmp)
        free(tmp);
    tmp = (void *)conf->user;
    if (tmp)
        free(tmp);
    tmp = (void *)conf->passwd;
    if (tmp)
        free(tmp);
    free(conf);
    
    return;
}

struct udps_config_t *find_config(struct udps_config_t *pos, struct udps_config_t *tmp_pos) {
    while (tmp_pos) {
        if (strcmp(pos->name, tmp_pos->name) == 0)
            return tmp_pos;
    }
    
    return NULL;
}

void copy_config(struct udps_config_t *prev_pos, struct udps_config_t *tmp_pos) {
    struct udps_config_t *tmp_conf = NULL;
    
    tmp_conf = malloc(sizeof(struct udps_config_t));
    if (tmp_pos->name)
        tmp_conf->name = strdup(tmp_pos->name);
    if (tmp_pos->user)
        tmp_conf->user = strdup(tmp_pos->user);
    if (tmp_pos->passwd)
        tmp_conf->passwd = strdup(tmp_pos->passwd);
    tmp_conf->auth_method = tmp_pos->auth_method;
    tmp_conf->client_ip = tmp_pos->client_ip;
    tmp_conf->connect_ip = tmp_pos->connect_ip;
    tmp_conf->connect_port = tmp_pos->connect_port;
    tmp_conf->nat_ip = tmp_pos->nat_ip;
    
    tmp_conf->next = prev_pos->next->next;
    release_config(prev_pos->next);
    prev_pos->next = tmp_conf;
    
    return;
}

int test_config(struct udps_config_t *pos, struct udps_config_t *tmp_pos) {
    if (pos->client_ip + pos->connect_ip + pos->connect_port + pos->nat_ip !=
        tmp_pos->client_ip + tmp_pos->connect_ip + tmp_pos->connect_port + tmp_pos->nat_ip)
        return 1;
    if (pos->auth_method != tmp_pos->auth_method)
        return 1;
    if (pos->auth_method)
        return (strcmp(pos->user, tmp_pos->user) || strcmp(pos->passwd, tmp_pos->passwd));
    
    return 0;
}

int reread_configuration_file(FILE *conf_fd) {
    struct udps_config_t *temp_config = NULL, *pos = NULL, *temp_pos = NULL, *prev_pos = NULL;
    
    if (parse_configuration_file(conf_fd, &temp_config))
        return ERR;
    
    pos = default_config;
    while (pos) {
        temp_pos = find_config(pos, temp_config);
        if (temp_pos == NULL) {
            /* remove config */
            prev_pos->next = pos->next;
            
            pthread_mutex_lock(&mutexusock);
            release_config(pos);
            pthread_mutex_unlock(&mutexusock);
            
            pos = prev_pos->next;
            continue;
        }
        if (test_config(pos, temp_pos)) {
            /* modify config */
            pthread_mutex_lock(&mutexusock);
            copy_config(prev_pos, temp_pos);
            pthread_mutex_unlock(&mutexusock);
        }
        prev_pos = pos;
        pos = pos->next;
    }
    
    temp_pos = temp_config->next;
    while (temp_pos) {
        pos = find_config(temp_pos, default_config);
        if (pos == NULL) {
            /* new config */
            pos = malloc(sizeof(struct udps_config_t));
            memmove(pos, temp_pos, sizeof(struct udps_config_t));
            pos->next = default_config->next;
            default_config->next = pos;
        }
        temp_pos = temp_pos->next;
    }
    
    return OK;
}
