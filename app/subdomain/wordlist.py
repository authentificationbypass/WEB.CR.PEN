# Comprehensive wordlist for subdomain brute-force enumeration.
# ~380 prefixes covering infrastructure, dev environments, admin tools,
# DevOps, databases, monitoring, storage, auth, CDN, and more.

SUBDOMAIN_PREFIXES: list[str] = [
    # Web / Core
    "www", "www2", "www3", "web", "web2", "home", "portal", "site",
    "m", "mobile", "wap", "pwa",

    # Mail
    "mail", "mail2", "mail3", "email", "webmail", "smtp", "smtp2",
    "smtp-relay", "mta", "mailer", "imap", "pop", "pop3", "mx", "mx1", "mx2",

    # DNS / Name Servers
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "resolver",

    # FTP
    "ftp", "ftp2", "sftp", "ftps", "files", "file", "fileserver",

    # VPN / Remote Access
    "vpn", "vpn2", "remote", "rdp", "ssh", "bastion", "jump", "jumphost",
    "gateway", "gw",

    # API
    "api", "api2", "api3", "api-v1", "api-v2", "api-v3",
    "api-dev", "api-staging", "api-prod", "api-internal",
    "rest", "graphql", "grpc", "ws", "websocket",

    # Application
    "app", "app2", "apps", "application",
    "service", "services", "backend", "frontend",
    "platform", "dashboard",

    # Admin / Management
    "admin", "admin2", "administrator", "administration",
    "panel", "controlpanel", "adminpanel", "cpanel", "whm", "plesk",
    "manage", "management", "console", "control",
    "backoffice", "sysadmin", "webadmin", "mgmt",
    "phpmyadmin", "pma", "adminer",

    # DevOps / Version Control
    "git", "gitlab", "gitea", "gogs", "bitbucket",
    "svn", "subversion", "cvs",
    "jenkins", "jenkins2", "ci", "ci2", "build", "buildbot",
    "teamcity", "bamboo", "circle", "travis", "drone", "woodpecker",
    "argocd", "argo", "flux",
    "deploy", "deployment", "release", "releases",
    "registry", "docker", "containers",
    "kubernetes", "k8s", "helm", "rancher", "portainer", "nomad",
    "consul", "vault", "terraform", "ansible",

    # Development Environments
    "dev", "dev2", "dev3", "develop", "development", "developer",
    "staging", "staging2", "stage", "stg",
    "test", "test2", "test3", "testing", "tests", "tst",
    "qa", "qa2", "uat", "sit", "integration",
    "preview", "preview2", "demo", "sandbox", "sandbox2",
    "lab", "lab2", "labs", "poc", "poc2",
    "alpha", "beta", "beta2", "nightly", "canary",
    "pre", "preprod", "pre-prod", "preproduction",

    # Monitoring / Observability
    "grafana", "prometheus", "alertmanager",
    "kibana", "elasticsearch", "elastic", "logstash",
    "sentry", "glitchtip", "bugsnag",
    "datadog", "newrelic", "dynatrace",
    "zabbix", "nagios", "icinga", "prtg", "netdata",
    "jaeger", "zipkin", "tracing", "opentelemetry",
    "logs", "log", "logging",
    "metrics", "stats", "statistics",
    "health", "healthcheck", "status", "uptime",
    "monitor", "monitoring",

    # Databases
    "db", "db1", "db2", "db3", "database",
    "mysql", "maria", "mariadb",
    "postgres", "postgresql", "pgsql",
    "mongo", "mongodb",
    "redis", "cache", "memcache", "memcached",
    "cassandra", "couchdb", "couchbase",
    "oracle", "mssql", "sqlserver",
    "clickhouse", "influxdb", "timeseries",
    "neo4j", "graphdb",

    # Storage / CDN
    "storage", "store", "cdn", "cdn2", "cdn3",
    "assets", "assets2", "static", "static2",
    "media", "media2", "images", "img", "img2",
    "video", "videos", "audio",
    "uploads", "upload", "download", "downloads",
    "bucket", "s3", "blob", "d", "dl",
    "nfs", "nas",
    "backup", "backup2", "backups", "bkp", "bak", "archive",

    # Auth / Identity
    "auth", "authentication", "login", "signin", "signup",
    "sso", "saml", "oauth", "oauth2", "openid", "oidc",
    "iam", "identity", "idp", "accounts", "account",
    "keycloak", "okta", "auth0", "authentik",
    "ldap", "ad", "directory", "password",

    # Security
    "security", "sec", "waf", "firewall",
    "certs", "certificates", "pki", "ca", "acme",
    "vpn2", "scan", "scanner",

    # Communication / Collaboration
    "chat", "messaging",
    "jira", "redmine", "mantis", "linear",
    "confluence", "wiki", "docs", "documentation",
    "knowledge", "kb", "helpdesk", "support", "help",
    "forum", "community", "blog", "news",
    "newsletter", "marketing",
    "meet", "video-conf",

    # CMS / E-Commerce
    "wordpress", "wp", "cms", "drupal", "magento",
    "shop", "store2", "ecommerce", "cart",
    "payment", "pay", "checkout", "billing",
    "invoice",

    # Network / Infrastructure
    "lb", "loadbalancer", "haproxy", "nginx", "proxy", "proxy2",
    "node", "node1", "node2", "node3",
    "server", "server1", "server2",
    "host", "host1", "host2",
    "edge", "edge1", "edge2",
    "cluster", "master", "replica", "slave",
    "ntp", "time", "internal", "intranet", "extranet",
    "private", "public",

    # Analytics / Tracking
    "analytics", "tracking", "pixel", "attribution",
    "search", "solr", "sphinx",
    "push", "notify", "notifications", "webhooks",

    # Geographic / Regional
    "us", "us-east", "us-west", "us1", "us2",
    "eu", "eu-west", "eu-central", "eu1", "eu2",
    "de", "uk", "fr", "nl", "sg", "au", "br", "jp", "ca",
    "asia", "apac", "latam",

    # Legacy / Versioned
    "v1", "v2", "v3", "old", "legacy", "classic", "new", "next",

    # Other High-Value
    "careers", "jobs", "hr",
    "maps", "geo", "location",
    "partner", "partners", "affiliate",
    "corporate", "corp",
    "ext", "external", "int",
    "printer", "print",
    "erp", "crm", "pos",
    "reporting", "reports", "bi",
]
